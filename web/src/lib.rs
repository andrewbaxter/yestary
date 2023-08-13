use std::{
    rc::Rc,
    cell::{
        RefCell,
    },
    collections::{
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
    utils::{
        window,
    },
};
use js_sys::Uint8Array;
use lunk::{
    EventGraph,
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
        Parse,
    },
    packet::{
        self,
        key::{
            PublicParts,
            UnspecifiedRole,
        },
        Key,
    },
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
    verified: bool,
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

struct MyFile {
    name: String,
    state: Prim<Rc<FileState>>,
}

#[derive(Clone, Copy)]
enum DocumentVerifiedState {
    Unknown,
    Yes(DateTime<Utc>),
    No,
}

enum FileState {
    Init,
    Inter {
        _future_drop: Box<dyn ScopeValue>,
    },
    Stamp {
        stamp: Stamp,
    },
    Document {
        hash: String,
        verified: DocumentVerifiedState,
    },
    Error,
}

impl PartialEq for FileState {
    fn eq(&self, other: &Self) -> bool {
        return core::mem::discriminant(self) == core::mem::discriminant(other);
    }
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

fn process_file(
    pc: &mut ProcessingContext,
    base_url: &String,
    public_keys:
        &Rc<RefCell<HashMap<String, broadcast::Receiver<Result<Key<PublicParts, UnspecifiedRole>, StrError>>>>>,
    files: &lunk::Vec<Rc<MyFile>>,
    file: File,
) {
    match file.name().rsplitn(2, ".").next().unwrap_throw() {
        "notify_stamp" => {
            process_stamp_file(pc, &base_url, &public_keys, &files, file);
        },
        _ => {
            process_doc_file(pc, &files, file);
        },
    }
}

fn process_doc_file(pc: &mut ProcessingContext, files: &lunk::Vec<Rc<MyFile>>, file: File) {
    let out = Rc::new(MyFile {
        name: file.name(),
        state: Prim::new(pc, Rc::new(FileState::Init)),
    });
    let (cancel_set, cancel) = oneshot::channel::<()>();
    let eg = pc.eg();
    spawn_local({
        let mut stream =
            ReadableStream::into_stream(ReadableStream::from_raw(file.stream().dyn_into().unwrap_throw()));
        let files = files.clone();
        let out = out.clone();
        let body = async move {
            let mut hash = Sha256::new();
            while let Some(Ok(chunk)) = stream.next().await {
                let bytes = Uint8Array::from(chunk).to_vec();
                hash.input(&bytes);
            }
            eg.event(|pc| {
                let mut delete = vec![];
                let out_state;

                // Finish the row with the result
                let hash = hash.result_str();
                let mut verified = DocumentVerifiedState::Unknown;
                for (other_i, other) in files.borrow().value().iter().enumerate() {
                    match other.state.borrow().get().as_ref() {
                        FileState::Stamp { stamp: other_stamp } if other_stamp.hash == hash => {
                            delete.push(other_i);
                            verified = match other_stamp.verified {
                                true => DocumentVerifiedState::Yes(other_stamp.stamp),
                                false => DocumentVerifiedState::No,
                            };
                        },
                        _ => { },
                    }
                }
                out_state = FileState::Document {
                    hash: hash,
                    verified: verified,
                };
                delete.sort();
                delete.reverse();
                for i in delete {
                    files.splice(pc, i, 1, vec![]);
                }

                // And in any case, finish the current element (may have been deleted above, ok)
                out.state.set(pc, Rc::new(out_state));
            });
        };
        async move {
            select!{
                _ = cancel =>(),
                _ = body =>(),
            }
        }
    });
    out.state.set(pc, Rc::new(FileState::Inter { _future_drop: scope_any(defer::defer(move || {
        cancel_set.send(()).unwrap_throw();
    })) }));
    files.push(pc, out);
}

fn process_stamp_file(
    pc: &mut ProcessingContext,
    base_url: &String,
    public_keys:
        &Rc<RefCell<HashMap<String, broadcast::Receiver<Result<Key<PublicParts, UnspecifiedRole>, StrError>>>>>,
    files: &lunk::Vec<Rc<MyFile>>,
    file: File,
) {
    let out = Rc::new(MyFile {
        name: file.name(),
        state: Prim::new(pc, Rc::new(FileState::Init)),
    });
    let (cancel_set, cancel) = oneshot::channel::<()>();
    spawn_local({
        let mut stream =
            ReadableStream::into_stream(ReadableStream::from_raw(file.stream().dyn_into().unwrap_throw()));
        let out = out.clone();
        let files = files.clone();
        let public_keys = public_keys.clone();
        let base_url = base_url.clone();
        let eg = pc.eg();
        let body = async move {
            let a = {
                let eg = eg.clone();
                let out = out.clone();
                async move {
                    let mut data = vec![];
                    while let Some(Ok(chunk)) = stream.next().await {
                        data.extend(Uint8Array::from(chunk).to_vec());
                    }
                    let outer_serial =
                        serde_json::from_slice::<SerialStamp>(&data).context("Error deserializing stamp")?;
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
                    let mut sig =
                        match Packet::from_bytes(
                            &hex::decode(&outer_serial.signature).context("Error decoding signature hex")?,
                        ).context("Error reading signature packet")? {
                            Packet::Signature(sig) => sig,
                            x => return Err(
                                StrError(format!("Signature data is not a signature, got {:?}", x.tag())),
                            ),
                        };
                    let verified =
                        sig
                            .verify_message(
                                &key,
                                &hex::decode(&outer_serial.message).context("Error parsing signature message hex")?,
                            )
                            .is_ok();

                    // Finish the row with the result
                    eg.event(|pc| {
                        let mut used_stamp = false;
                        let mut stamp_index = None;
                        for (other_i, other) in files.borrow().value().iter().enumerate() {
                            let hash = match other.state.borrow().get().as_ref() {
                                FileState::Document { hash: other_hash, .. } => {
                                    other_hash.clone()
                                },
                                FileState::Stamp { stamp: other_stamp } if other_stamp.hash == inner_serial.hash => {
                                    stamp_index = Some(other_i);
                                    continue;
                                },
                                _ => {
                                    continue;
                                },
                            };
                            used_stamp = true;
                            other.state.set(pc, Rc::new(FileState::Document {
                                hash: hash,
                                verified: match verified {
                                    true => DocumentVerifiedState::Yes(inner_serial.stamp),
                                    false => DocumentVerifiedState::No,
                                },
                            }));
                        }
                        if used_stamp {
                            if let Some(i) = stamp_index {
                                files.splice(pc, i, 1, vec![]);
                            }
                        } else {
                            out.state.set(pc, Rc::new(FileState::Stamp { stamp: Stamp {
                                hash: inner_serial.hash,
                                stamp: inner_serial.stamp,
                                verified: verified,
                            } }));
                        }
                    });
                    return Ok(());
                }
            };
            match a.await {
                Ok(_) => { },
                Err(e) => {
                    console_dbg!("Error reading file", out.name, e);
                    eg.event(|pc| {
                        out.state.set(pc, Rc::new(FileState::Error));
                    });
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
    out.state.set(pc, Rc::new(FileState::Inter { _future_drop: scope_any(defer::defer(move || {
        cancel_set.send(()).unwrap_throw();
    })) }));
    files.push(pc, out);
}

fn file_el(pc: &mut ProcessingContext, base_url: &String, f: &Rc<MyFile>) -> ScopeElement {
    return el("div").classes(&["file"]).drop(|div| link!((
        _pc = pc;
        state = f.state.clone();
        f = f.clone(),
        div = div.clone(),
        base_url = base_url.clone(),
    ) {
        div.mut_clear();
        match state.borrow().get().as_ref() {
            FileState::Init => {
                div.mut_push(el("div").push(el("span").text(&f.name)));
            },
            FileState::Inter { .. } => {
                div.mut_push(
                    el(
                        "div",
                    ).extend(
                        vec![
                            el("svg")
                                .classes(&["spinner"])
                                .attr("viewBox", "0 0 1 1")
                                .attr("xmlns", "http://www.w3.org/2000/svg")
                                .attr("style", "width: 1cm; height: 1cm")
                                .push(el("circle").attr("cx", "0.5").attr("cy", "0.5").attr("r", "0.35")),
                            el("span").text(&f.name)
                        ],
                    ),
                );
            },
            FileState::Stamp { .. } => {
                div.mut_push(
                    el("div").extend(vec![el("img").attr("src", "stamp.svg"), el("span").text(&f.name)]),
                );
            },
            FileState::Document { hash, verified } => match verified {
                DocumentVerifiedState::Unknown => {
                    div.mut_push(
                        el("a")
                            .attr("href", &format!("{}/api/stamp/{}", base_url, hash))
                            .attr("download", &format!("{}.stamp", f.name))
                            .extend(vec![el("img").attr("src", "doc.svg"), el("span").text(&f.name)]),
                    );
                },
                DocumentVerifiedState::Yes(stamp) => {
                    div.mut_push(
                        el(
                            "div",
                        ).extend(
                            vec![
                                el("img").attr("src", "yes.svg"),
                                el("span").text(&f.name),
                                el("time")
                                    .attr("datetime", &stamp.to_rfc3339())
                                    .text(&stamp.format("%Y-%m-%d").to_string())
                            ],
                        ),
                    );
                },
                DocumentVerifiedState::No => {
                    div.mut_push(
                        el("div").extend(vec![el("img").attr("src", "no.svg"), el("span").text(&f.name)]),
                    );
                },
            },
            FileState::Error => {
                div.mut_push(
                    el("div").extend(vec![el("img").attr("src", "error.svg"), el("span").text(&f.name)]),
                );
            },
        }
    }));
}

#[wasm_bindgen(start)]
fn main() {
    let eg = EventGraph::new();
    eg.event(|pc| {
        let files: lunk::Vec<_> = lunk::Vec::new(pc, vec![]);
        let base_url = window().location().origin().unwrap_throw();
        let public_keys = Rc::new(RefCell::new(HashMap::new()));
        set_root(
            vec![
                el("div")
                    .classes(&["header"])
                    .extend(
                        vec![
                            el("a")
                                .attr("href", "https://github.com/andrewbaxter/yestify")
                                .push(el("img").attr("src", "logo.svg"))
                        ],
                    ),
                el("div")
                    .classes(&["file_button"])
                    .extend(
                        vec![
                            el(
                                "label",
                            ).extend(vec![el("input").attr("type", "file").attr("multiple", "true").on("change", {
                                let base_url = base_url.clone();
                                let public_keys = public_keys.clone();
                                let files = files.clone();
                                let eg = pc.eg();
                                move |e| eg.event(|pc| {
                                    let e = e.target().unwrap_throw();
                                    let el = e.dyn_ref::<HtmlInputElement>().unwrap_throw();
                                    let js_files = el.files().unwrap_throw();
                                    for i in 0 .. js_files.length() {
                                        let file = js_files.get(i).unwrap_throw();
                                        process_file(pc, &base_url, &public_keys, &files, file);
                                    }
                                })
                            }), el("img").attr("src", "drop.svg")]),
                            el("div").drop(|e| {
                                link!((
                                    pc = pc;
                                    files = files.clone();
                                    base_url = base_url.clone(),
                                    e = e.clone()
                                ) {
                                    for c in files.borrow().changes() {
                                        e.mut_splice(c.offset, c.remove, c.add.iter().map(|f| {
                                            return file_el(pc, &base_url, f);
                                        }).collect());
                                    }
                                });
                            })
                        ],
                    )
                    .on("dragover", |e| {
                        e.prevent_default();
                    })
                    .on("drop", {
                        let public_keys = public_keys.clone();
                        let files = files.clone();
                        let base_url = base_url.clone();
                        let eg = pc.eg();
                        move |e| eg.event(|pc| {
                            e.prevent_default();
                            let e = e.dyn_ref::<DragEvent>().unwrap_throw();
                            let datatransfer = e.data_transfer().unwrap_throw();
                            if let Some(js_files) = datatransfer.files() {
                                for i in 0 .. js_files.length() {
                                    process_file(
                                        pc,
                                        &base_url,
                                        &public_keys,
                                        &files,
                                        js_files.get(i).unwrap_throw(),
                                    );
                                }
                            }
                            let items = datatransfer.items();
                            for i in 0 .. items.length() {
                                let Some(file) = items.get(i).unwrap_throw().get_as_file().unwrap_throw() else {
                                    continue;
                                };
                                process_file(pc, &base_url, &public_keys, &files, file);
                            }
                        })
                    }),
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
