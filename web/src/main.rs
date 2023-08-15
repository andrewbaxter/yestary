use std::{
    rc::Rc,
    cell::{
        RefCell,
    },
    collections::{
        HashMap,
    },
    fmt::Display,
    str::FromStr,
};
use chrono::{
    DateTime,
    Utc,
};
use sha2::{
    Sha256,
    Digest,
};
use futures::{
    channel::oneshot,
    StreamExt,
};
use gloo::{
    console::console_dbg,
    utils::{
        window,
        document,
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
    el_from_raw,
};
use sequoia_openpgp::{
    parse::{
        Parse,
    },
    Packet,
    Message,
    Cert,
};
use shared::{
    SerialStamp,
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

const SUFFIX: &'static str = "notary_stamp";

#[derive(PartialEq)]
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

#[derive(Clone, Copy, PartialEq)]
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
        match (self, other) {
            (Self::Inter { .. }, Self::Inter { .. }) => false,
            (Self::Stamp { stamp: l_stamp }, Self::Stamp { stamp: r_stamp }) => l_stamp == r_stamp,
            (
                Self::Document { hash: l_hash, verified: l_verified },
                Self::Document { hash: r_hash, verified: r_verified },
            ) => l_hash ==
                r_hash &&
                l_verified == r_verified,
            _ => core::mem::discriminant(self) == core::mem::discriminant(other),
        }
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

fn icon(name: &str) -> ScopeElement {
    return el("div").classes(&["icon", &format!("icon_{}", name)]);
}

fn icon2(name1: &str, name2: &str) -> ScopeElement {
    return el("div").classes(&["icon-stack"]).extend(vec![icon(name1), icon(name2)]);
}

fn process_file(
    pc: &mut ProcessingContext,
    base_url: &String,
    public_keys: &Rc<RefCell<HashMap<Vec<u8>, broadcast::Receiver<Result<Cert, StrError>>>>>,
    files: &lunk::Vec<Rc<MyFile>>,
    file: File,
) {
    match file.name().rsplitn(2, ".").next().unwrap_throw() {
        SUFFIX => {
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
                hash.update(&bytes);
            }
            eg.event(|pc| {
                console_dbg!("start process doc event");
                let mut delete = vec![];
                let out_state;

                // Finish the row with the result
                let hash = hex::encode(&hash.finalize());
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
                console_dbg!("end of doc file finish event");
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
    public_keys: &Rc<RefCell<HashMap<Vec<u8>, broadcast::Receiver<Result<Cert, StrError>>>>>,
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
                    let signature = Message::from_bytes(&data).context("Error decoding sq signature")?;
                    let mut children = signature.children();
                    let Some(Packet::OnePassSig(sign0)) = children.next() else {
                        return Err(StrError("Missing signature packet 1, bad signature".to_string()));
                    };
                    let key: Cert = match sign0.issuer() {
                        sequoia_openpgp::KeyID::V4(keyid) => {
                            let keyid = keyid.to_vec();
                            let hex_keyid = hex::encode(&keyid);
                            public_keys.borrow_mut().entry(keyid).or_insert_with(|| {
                                let (res_set, res) = broadcast::channel(1);
                                spawn_local(async move {
                                    res_set.send(async move {
                                        let key_str =
                                            reqwasm::http::Request::get(
                                                &format!("{}/api/key/{}", base_url, hex_keyid),
                                            )
                                                .send()
                                                .await
                                                .context("Error during key request")?
                                                .text()
                                                .await
                                                .context("Error reading key response")?;
                                        return Ok(
                                            Cert::from_str(&key_str).context("Error parsing sq pub key (cert)")?,
                                        );
                                    }.await).unwrap_throw();
                                });
                                res
                            }).recv().await.context("Error getting result from key channel")??
                        },
                        i => return Err(StrError(format!("Unknown key id type: {:?}", i))),
                    };
                    let Some(Packet::Literal(body)) = children.next() else {
                        return Err(StrError("Missing literal, bad signature".to_string()));
                    };
                    let Some(Packet:: Signature(mut sign1)) = children.next().cloned() else {
                        return Err(StrError("Missing signature packet 2, bad signature".to_string()));
                    };
                    let stamp: SerialStamp = serde_json::from_slice(body.body()).context("Couldn't parse body")?;
                    let verified =
                        sign1.verify_message(key.primary_key().parts_into_public().key(), body.body()).is_ok();

                    // Finish the row with the result
                    eg.event(|pc| {
                        console_dbg!("start process stamp event");
                        let mut used_stamp = false;
                        let mut stamp_index = None;
                        for (other_i, other) in files.borrow().value().iter().enumerate() {
                            if other.name == out.name {
                                stamp_index = Some(other_i);
                                continue;
                            }
                            let hash = match other.state.borrow().get().as_ref() {
                                FileState::Document { hash: other_hash, .. } => {
                                    other_hash.clone()
                                },
                                _ => {
                                    continue;
                                },
                            };
                            used_stamp = true;
                            console_dbg!("setting other state verified", other.name);
                            other.state.set(pc, Rc::new(FileState::Document {
                                hash: hash,
                                verified: match verified {
                                    true => DocumentVerifiedState::Yes(stamp.stamp),
                                    false => DocumentVerifiedState::No,
                                },
                            }));
                        }
                        if used_stamp {
                            if let Some(i) = stamp_index {
                                console_dbg!("used stamp, clearing");
                                files.splice(pc, i, 1, vec![]);
                            }
                        } else {
                            out.state.set(pc, Rc::new(FileState::Stamp { stamp: Stamp {
                                hash: stamp.hash,
                                stamp: stamp.stamp,
                                verified: verified,
                            } }));
                        }
                        console_dbg!("end of stamp file finish event");
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
        console_dbg!("file state changeddd");
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
                            el_from_raw(
                                document()
                                    .create_element_ns(Some("http://www.w3.org/2000/svg"), "svg")
                                    .unwrap_throw(),
                            )
                                .classes(&["spinner"])
                                .attr("viewBox", "0 0 1 1")
                                .push(
                                    el_from_raw(
                                        document()
                                            .create_element_ns(Some("http://www.w3.org/2000/svg"), "circle")
                                            .unwrap_throw(),
                                    )
                                        .attr("cx", "0.5")
                                        .attr("cy", "0.5")
                                        .attr("r", "0.35"),
                                ),
                            el("span").text(&f.name)
                        ],
                    ),
                );
            },
            FileState::Stamp { .. } => {
                div.mut_push(el("div").extend(vec![icon("badge"), el("span").text(&f.name)]));
            },
            FileState::Document { hash, verified } => match verified {
                DocumentVerifiedState::Unknown => {
                    console_dbg!("verified still unknonwn");
                    div.mut_push(
                        el("a")
                            .attr("href", &format!("{}/api/stamp/{}", base_url, hash))
                            .attr("download", &format!("{}.{}", f.name, SUFFIX))
                            .extend(vec![icon("doc"), el("span").text(&f.name)]),
                    );
                },
                DocumentVerifiedState::Yes(stamp) => {
                    console_dbg!("verified yes");
                    div.mut_push(
                        el(
                            "div",
                        ).extend(
                            vec![
                                icon2("doc", "check"),
                                el("span").text(&f.name),
                                el("time")
                                    .attr("datetime", &stamp.to_rfc3339())
                                    .text(&stamp.format("%Y-%m-%d").to_string())
                            ],
                        ),
                    );
                },
                DocumentVerifiedState::No => {
                    div.mut_push(el("div").extend(vec![icon2("doc", "cross"), el("span").text(&f.name)]));
                },
            },
            FileState::Error => {
                div.mut_push(el("div").extend(vec![icon("error"), el("span").text(&f.name)]));
            },
        }
    }));
}

fn main() {
    let eg = EventGraph::new();
    eg.event(|pc| {
        console_dbg!("start setup event");
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
                                .attr("href", "https://github.com/andrewbaxter/yestary")
                                .push(el("img").attr("src", "public/logo.svg"))
                        ],
                    ),
                el("div").classes(&["file_button"]).extend(vec![
                    el("div").drop(|e| link!((
                        pc = pc;
                        files = files.clone();
                        base_url = base_url.clone(),
                        e = e.clone()
                    ) {
                        for c in files.borrow().changes() {
                            console_dbg!(
                                format!("change files at {} remove {} add {}", c.offset, c.remove, c.add.len())
                            );
                            e.mut_splice(c.offset, c.remove, c.add.iter().map(|f| {
                                return file_el(pc, &base_url, f);
                            }).collect());
                        }
                    })),
                    el(
                        "label",
                    ).extend(vec![el("input").attr("type", "file").attr("multiple", "true").on("change", {
                        let base_url = base_url.clone();
                        let public_keys = public_keys.clone();
                        let files = files.clone();
                        let eg = pc.eg();
                        move |e| eg.event(|pc| {
                            console_dbg!("start new files event 1");
                            let e = e.target().unwrap_throw();
                            let el = e.dyn_ref::<HtmlInputElement>().unwrap_throw();
                            let js_files = el.files().unwrap_throw();
                            for i in 0 .. js_files.length() {
                                let file = js_files.get(i).unwrap_throw();
                                process_file(pc, &base_url, &public_keys, &files, file);
                            }
                            console_dbg!("end of new files event 1");
                        })
                    }), icon("drop")])
                ]).on("dragover", |e| {
                    e.prevent_default();
                }).on("drop", {
                    let public_keys = public_keys.clone();
                    let files = files.clone();
                    let base_url = base_url.clone();
                    let eg = pc.eg();
                    move |e| eg.event(|pc| {
                        console_dbg!("start new files event 2");
                        e.prevent_default();
                        let e = e.dyn_ref::<DragEvent>().unwrap_throw();
                        let datatransfer = e.data_transfer().unwrap_throw();
                        if let Some(js_files) = datatransfer.files() {
                            for i in 0 .. js_files.length() {
                                process_file(pc, &base_url, &public_keys, &files, js_files.get(i).unwrap_throw());
                            }
                        }
                        let items = datatransfer.items();
                        for i in 0 .. items.length() {
                            let Some(file) = items.get(i).unwrap_throw().get_as_file().unwrap_throw() else {
                                continue;
                            };
                            process_file(pc, &base_url, &public_keys, &files, file);
                        }
                        console_dbg!("end of new files event 2");
                    })
                }),
                el("div")
                    .classes(&["footer"])
                    .extend(
                        vec![el("span").text("© 2023 Andrew Baxter — Run your "), el("a").text("own instance")],
                    )
            ],
        );
        console_dbg!("end of setup event");
    });
}
