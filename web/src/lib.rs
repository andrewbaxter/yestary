use std::{
    rc::Rc,
    cell::{
        RefCell,
        Cell,
    },
    collections::{
        HashSet,
        HashMap,
    },
    fmt::Display,
};
use chrono::{
    DateTime,
    Utc,
};
use crypto::{
    sha2::Sha256,
    digest::Digest,
};
use futures::{
    channel::oneshot,
    StreamExt,
};
use gloo::{
    console::console_dbg,
    utils::window,
};
use js_sys::Uint8Array;
use lunk::{
    EventGraph,
    new_prim,
    new_vec,
    Prim,
    ProcessingContext,
    link,
};
use rooting::{
    set_root,
    el,
    ScopeElement,
    ScopeValue,
    scope_any,
};
use sequoia_openpgp::{
    parse::{
        stream::DetachedVerifierBuilder,
        Parse,
    },
    Cert,
    packet::{
        self,
        key::{
            PublicParts,
            UnspecifiedRole,
        },
        Key,
        signature::SignatureBuilder,
    },
    crypto::mpi::PublicKey,
    Packet,
};
use serde::{
    Deserialize,
    Serialize,
};
use tokio::{
    select,
    sync::broadcast,
};
use wasm_bindgen::{
    prelude::{
        wasm_bindgen,
        Closure,
    },
    JsCast,
    UnwrapThrowExt,
    JsValue,
};
use wasm_bindgen_futures::spawn_local;
use wasm_streams::ReadableStream;
use web_sys::{
    DragEvent,
    HtmlInputElement,
    ReadableStreamDefaultReader,
    File,
};

#[derive(Serialize, Deserialize)]
struct SerialStamp {
    message: String,
    signature: String,
    notary: String,
    key_fingerprint: String,
}

#[derive(Serialize, Deserialize)]
struct SerialStampInner {
    hash: String,
    stamp: DateTime<Utc>,
}

struct Stamp {
    hash: String,
    stamp: DateTime<Utc>,
    yes: bool,
}

// Wrong/missing in web-sys
#[wasm_bindgen]
extern "C" {
    /// A result returned by
    /// [`ReadableStreamDefaultReader.read`](https://developer.mozilla.org/en-US/docs/Web/API/ReadableStreamDefaultReader/read).
    #[derive(Clone, Debug)]
    pub type ReadableStreamDefaultReadResult;
    #[wasm_bindgen(method, getter, js_name = done)]
    pub fn is_done(this: &ReadableStreamDefaultReadResult) -> bool;
    #[wasm_bindgen(method, getter, js_name = value)]
    pub fn value(this: &ReadableStreamDefaultReadResult) -> JsValue;
}

struct BinFile {
    name: String,
    size: usize,
    received: Prim<usize>,
    state: BinFileState,
    stream: Option<Box<dyn ScopeValue>>,
}

enum BinFileState {
    Init,
    Receiving,
    Stamp {
        stamp: Stamp,
    },
    Document {
        hash: String,
    },
    Error,
}

#[derive(Clone, Debug)]
struct StrError(String);

trait StrErrorContext<T> {
    fn context(self, text: &str) -> Result<T, StrError>;
}

impl<T, E: Display> StrErrorContext<T> for Result<T, E> {
    fn context(self, text: &str) -> Result<T, StrError> {
        match self {
            Ok(x) => return Ok(x),
            Err(e) => return Err(StrError(format!("{}: {}", text, e))),
        };
    }
}

trait StrErrorContext2<T> {
    fn replace_err(self, text: &str) -> Result<T, StrError>;
}

impl<T, E> StrErrorContext2<T> for Result<T, E> {
    fn replace_err(self, text: &str) -> Result<T, StrError> {
        match self {
            Ok(x) => return Ok(x),
            Err(_) => return Err(StrError(text.to_string())),
        };
    }
}

#[derive(Clone)]
struct DoneFile {
    name: String,
    date: DateTime<Utc>,
    yes: bool,
}

fn process_file(
    pc: &mut ProcessingContext,
    base_url: &String,
    public_keys:
        &Rc<RefCell<HashMap<String, broadcast::Receiver<Result<Key<PublicParts, UnspecifiedRole>, StrError>>>>>,
    bin_files: &lunk::Vec<Rc<RefCell<BinFile>>>,
    done_files: &lunk::Vec<DoneFile>,
    file: File,
) {
    let out = Rc::new(RefCell::new(BinFile {
        name: file.name(),
        size: file.size() as usize,
        received: new_prim(pc, 0),
        state: BinFileState::Init,
        stream: None,
    }));

    enum ReadState {
        Stamp {
            data: Vec<u8>,
        },
        Document {
            hash: Sha256,
        },
    }

    let state = Rc::new(RefCell::new(match file.name().rsplitn(2, ".").next().unwrap_throw() {
        "notify_stamp" => {
            ReadState::Stamp { data: vec![] }
        },
        _ => {
            ReadState::Document { hash: Sha256::new() }
        },
    }));
    let (cancel_set, cancel) = oneshot::channel::<()>();
    spawn_local({
        let stream = ReadableStream::into_stream(ReadableStream::from_raw(file.stream().dyn_into().unwrap_throw()));
        let body = async move {
            match async move {
                // Read data
                while let Some(Ok(chunk)) = stream.next().await {
                    let bytes = Uint8Array::from(chunk).to_vec();
                    match &mut *state.borrow_mut() {
                        ReadState::Stamp { data } => {
                            data.extend(bytes);
                        },
                        ReadState::Document { hash } => {
                            hash.input(&bytes);
                        },
                    }
                }

                // Compile/finish read data
                let out_state;
                match &mut *state.borrow_mut() {
                    ReadState::Stamp { data } => {
                        // Parse signature
                        let outer_serial = serde_json::from_slice::<SerialStamp>(&data).context("Error deserializing stamp")?;
                        let inner_serial =
                            serde_json::from_str::<SerialStampInner>(
                                &outer_serial.message,
                            ).context("Error deserializing stamp inner")?;

                        // Get associated key, download if haven't already
                        let key: Key<PublicParts, _> =
                            public_keys.borrow_mut().entry(outer_serial.key_fingerprint.clone()).or_insert_with(|| {
                                let (res_set, res) = broadcast::channel(1);
                                spawn_local(async move {
                                    res_set.send(async move {
                                        let key_json =
                                            reqwasm::http::Request::get(
                                                &format!("{}/api/key/{}", base_url, outer_serial.key_fingerprint),
                                            )
                                                .send()
                                                .await
                                                .context("Error during key request")?
                                                .text()
                                                .await
                                                .context("Error reading key response")?;
                                        return Ok(
                                            packet::Key::from_bytes(
                                                &hex::decode(&key_json).context("Error decoding key hex")?,
                                            )
                                                .context("Error parsing key from key bytes")?
                                                .parts_into_public(),
                                        );
                                    }.await).unwrap_throw();
                                });
                                res
                            }).recv().await.context("Error getting result from key channel")??;

                        // Stamps are self-verifiable since they contain both the signature and message
                        // (hash). We can confirm that a document is verified by matching its hash with
                        // the hash in the stamp.
                        let sig =
                            match Packet::from_bytes(
                                &hex::decode(&outer_serial.signature).context("Error decoding signature hex")?,
                            ).context("Error reading signature packet")? {
                                Packet::Signature(sig) => sig,
                                x => return Err(
                                    StrError(format!("Signature data is not a signature, got {:?}", x.tag())),
                                ),
                            };

                        // Finish the row with the result
                        out_state = BinFileState::Stamp { stamp: Stamp {
                            hash: inner_serial.hash,
                            stamp: inner_serial.stamp,
                            yes: sig
                                .verify_message(
                                    &key,
                                    &hex::decode(
                                        &outer_serial.message,
                                    ).context("Error parsing signature message hex")?,
                                )
                                .is_ok(),
                        } };
                    },
                    ReadState::Document { hash } => {
                        // Finish the row with the result
                        out_state = BinFileState::Document { hash: hash.result_str() };
                    },
                };

                // Match immediately processable file pairs
                let mut delete = vec![];
                for (i, other) in bin_files.borrow().value().iter().enumerate() {
                    let other2 = other.borrow();
                    match other2.state {
                        BinFileState::Document { hash: other_hash } => match out_state {
                            BinFileState::Stamp { stamp } if other_hash == stamp.hash => {
                                delete.push(i);
                                done_files.push(pc, DoneFile {
                                    name: other2.name,
                                    date: stamp.stamp,
                                    yes: stamp.yes,
                                });
                            },
                            _ => { },
                        },
                        BinFileState::Stamp { stamp: other_stamp } => match out_state {
                            BinFileState::Stamp { stamp } if other_stamp.hash == stamp.hash => {
                                delete.push(i);
                            },
                            BinFileState::Document { hash } if other_stamp.hash == hash => {
                                delete.push(i);
                                done_files.push(pc, DoneFile {
                                    name: out.borrow().name,
                                    date: other_stamp.stamp,
                                    yes: other_stamp.yes,
                                });
                            },
                            _ => { },
                        },
                        _ => { },
                    }
                }
                delete.sort();
                delete.reverse();
                for i in delete {
                    bin_files.splice(pc, i, 1, vec![]);
                }

                // And in any case, finish the current element (may have been deleted above, ok)
                let mut out = out.borrow_mut();
                out.state = out_state;
                out.received.set(pc, out.size);
                out.stream = None;
                return Ok(());
            }.await {
                Ok(_) => { },
                Err(e) => {
                    let mut out = out.borrow_mut();
                    console_dbg!("Error reading file", out.name, e);
                    out.state = BinFileState::Error;
                    return;
                },
            }
        };
        async move {
            select!{
                _ = cancel =>(),
                _ = body =>(),
            }
        }
    });
    out.borrow_mut().stream = Some(scope_any(defer::defer(move || {
        cancel_set.send(()).unwrap_throw();
    })));
    bin_files.push(pc, out);
}

fn main_button() -> ScopeElement { }

fn icon(name: &'static str) -> ScopeElement { }

#[wasm_bindgen(start)]
fn main() {
    let eg = EventGraph::new();
    eg.event(|pc| {
        let document = new_prim(pc, None);
        let signature = new_prim(pc, None);
        let bin_files: lunk::Vec<_> = new_vec(pc, vec![]);
        let done_files: lunk::Vec<_> = new_vec(pc, vec![]);
        let base_url = window().location().origin().unwrap_throw();
        let public_keys = Rc::new(RefCell::new(HashMap::new()));
        set_root(
            vec![
                el("div")
                    .classes(&["header"])
                    .extend(
                        vec![
                            el("a")
                                .attr("href", "https://github.com/andrewbaxter/notar")
                                .push(el("img").attr("src", "logo.svg"))
                        ],
                    ),
                el("div")
                    .classes(&["main-buttons"])
                    .extend(
                        vec![
                            el("div")
                                .classes(&["file_button"])
                                .push(
                                    el(
                                        "label",
                                    ).push(
                                        el("input")
                                            .attr("type", "file")
                                            .attr("multiple", "true")
                                            .listen("change", |e| eg.event(|pc| {
                                                let el =
                                                    e
                                                        .target()
                                                        .unwrap_throw()
                                                        .dyn_ref::<HtmlInputElement>()
                                                        .unwrap_throw();
                                                let files = el.files().unwrap_throw();
                                                for i in 0 .. files.length() {
                                                    process_file(
                                                        pc,
                                                        &base_url,
                                                        &public_keys,
                                                        &bin_files,
                                                        &done_files,
                                                        files.get(i).unwrap_throw(),
                                                    );
                                                }
                                            })),
                                    ),
                                )
                                .listen("dragover", |e| {
                                    e.prevent_default();
                                })
                                .listen("drop", |e| eg.event(|pc| {
                                    e.prevent_default();
                                    let e = e.dyn_ref::<DragEvent>().unwrap_throw();
                                    let datatransfer = e.data_transfer().unwrap_throw();
                                    if let Some(files) = datatransfer.files() {
                                        for i in 0 .. files.length() {
                                            process_file(
                                                pc,
                                                &base_url,
                                                &public_keys,
                                                &bin_files,
                                                &done_files,
                                                files.get(i).unwrap_throw(),
                                            );
                                        }
                                    }
                                    let items = datatransfer.items();
                                    for i in 0 .. items.length() {
                                        let Some(
                                            file
                                        ) = items.get(i).unwrap_throw().get_as_file().unwrap_throw() else {
                                            continue;
                                        };
                                        process_file(pc, &base_url, &public_keys, &bin_files, &done_files, file);
                                    }
                                })),
                            main_button().classes(&["button_clear"]).push(icon("clear")).drop(|e| {
                                link!((
                                    pc = pc;
                                    bin_files = bin_files.clone();
                                    e = e.clone()
                                ) {
                                    let classes = ["disable"];
                                    if bin_files.borrow().value().is_empty() {
                                        e.mut_classes(&classes);
                                    } else {
                                        e.mut_remove_classes(&classes);
                                    }
                                })
                            }).listen("click", move |_| {
                                eg.event(|pc| {
                                    bin_files.clear(pc);
                                });
                            }),
                            main_button().push(icon("stamp")).drop(|e| {
                                link!((
                                    pc = pc;
                                    bin_files = bin_files.clone();
                                    e = e.clone()
                                ) {
                                    let classes = ["disable"];
                                    if !bin_files
                                        .borrow()
                                        .value()
                                        .iter()
                                        .map(|x| matches!(x.borrow().state, BinFileState::Document { .. }))
                                        .next()
                                        .unwrap_or(false) {
                                        e.mut_classes(&classes);
                                    } else {
                                        e.mut_remove_classes(&classes);
                                    }
                                })
                            }).listen("click", move |_| {
                                eg.event(|pc| {
                                    for f in bin_files.borrow().value() {
                                        match f.borrow().state {
                                            BinFileState::Document { hash } => todo!(),
                                        }
                                    }
                                });
                            })
                        ],
                    ),
                el("div").classes(&["main-list"]),
                el("div")
                    .classes(&["footer"])
                    .extend(
                        vec![
                            el("span").text("&copy; 2023 Andrew Baxter &em; Run your "),
                            el("a").text("own instance")
                        ],
                    )
            ],
        );
    });
}
