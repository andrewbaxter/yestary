use std::{
    rc::Rc,
    cell::{
        RefCell,
        Cell,
    },
};
use chrono::{
    DateTime,
    Utc,
};
use crypto::{
    sha2::Sha256,
    digest::Digest,
};
use gloo::console::console_dbg;
use js_sys::Uint8Array;
use lunk::{
    EventGraph,
    new_prim,
    new_vec,
    Prim,
};
use rooting::{
    set_root,
    el,
    ScopeElement,
    ScopeValue,
};
use serde::{
    Deserialize,
    Serialize,
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
use web_sys::{
    DragEvent,
    HtmlInputElement,
    ReadableStreamDefaultReader,
};

#[derive(Serialize, Deserialize)]
struct SerialStamp {
    text: String,
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
    text: String,
    key_fingerprint: String,
    signature: String,
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

struct BinStampState {
    data: Vec<u8>,
}

struct BinDocState {
    hash: Sha256,
}

#[derive(Clone)]
struct DoneFile {
    name: String,
    date: DateTime<Utc>,
    yes: bool,
}

fn file_button(
    eg: EventGraph,
    done_files: lunk::Vec<DoneFile>,
    bin_files: lunk::Vec<Rc<RefCell<BinFile>>>,
) -> ScopeElement {
    return el("label")
        .classes(&["file_button"])
        .push(el("input").attr("type", "file").attr("multiple", "true").listen("change", |e| eg.event(|pc| {
            let el = e.target().unwrap_throw().dyn_ref::<HtmlInputElement>().unwrap_throw();
            let files = el.files().unwrap_throw();
        })))
        .listen("dragover", |e| {
            e.prevent_default();
        })
        .listen("drop", |e| eg.event(|pc| {
            e.prevent_default();
            let e = e.dyn_ref::<DragEvent>().unwrap_throw();
            let datatransfer = e.data_transfer().unwrap_throw();
            if let Some(files) = datatransfer.files() {
                for i in 0 .. files.length() {
                    let file = files.get(i).unwrap_throw();
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
                    let reader = ReadableStreamDefaultReader::from(file.stream().get_reader().into());
                    let callbacks = Rc::new(RefCell::new(None));
                    let chunk_cb = Closure::new({
                        let callbacks = callbacks.clone();
                        let out = Rc::downgrade(&out);
                        let eg = eg.clone();
                        move |e| eg.event(|pc| {
                            let e = ReadableStreamDefaultReadResult::from(e);
                            let out = out.upgrade().unwrap();
                            if e.is_done() {
                                let out_state;
                                match &mut *state.borrow_mut() {
                                    ReadState::Stamp { data } => {
                                        match serde_json::from_slice::<SerialStamp>(
                                            &data,
                                        ).and_then(
                                            |stamp| serde_json::from_str::<SerialStampInner>(
                                                &stamp.text,
                                            ).map(move |inner| Stamp {
                                                hash: inner.hash,
                                                stamp: inner.stamp,
                                                text: stamp.text,
                                                signature: stamp.signature,
                                            }),
                                        ) {
                                            Ok(s) => {
                                                out_state = BinFileState::Stamp { stamp: s };
                                            },
                                            Err(e) => {
                                                let mut out = out.borrow_mut();
                                                console_dbg!("Error reading file", out.name, e);
                                                out.state = BinFileState::Error;
                                                return;
                                            },
                                        }
                                    },
                                    ReadState::Document { hash } => {
                                        out_state = BinFileState::Document { hash: hash.result_str() };
                                    },
                                };
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
                                                    yes: stamp.verify(hash),
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
                                                    yes: other_stamp.verify(hash),
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
                                {
                                    let mut out = out.borrow_mut();
                                    out.state = out_state;
                                    out.received.set(pc, out.size);
                                    out.stream = None;
                                }
                            } else {
                                let bytes = Uint8Array::from(e.value()).to_vec();
                                match &mut *state.borrow_mut() {
                                    ReadState::Stamp { data } => {
                                        data.extend(bytes);
                                    },
                                    ReadState::Document { hash } => {
                                        hash.input(&bytes);
                                    },
                                }
                                let (chunk_cb, error_cb) = callbacks.borrow().unwrap();
                                reader.read().then2(chunk_cb.borrow(), error_cb.borrow());
                            }
                        })
                    });
                    let error_cb = Closure::new({
                        let out = Rc::downgrade(&out);
                        move |e| {
                            let out = out.upgrade().unwrap_throw();
                            let mut out = out.borrow_mut();
                            console_dbg!("Error reading file", out.name, e);
                            out.state = BinFileState::Error;
                            out.stream = None;
                        }
                    });
                    reader.read().then2(&chunk_cb, &error_cb);
                    *callbacks.borrow_mut() = Some((Rc::new(chunk_cb), Rc::new(error_cb)));
                    out.borrow_mut().stream;
                    bin_files.push(pc, out);
                }
            }
            datatransfer.items();
        }));
}

#[wasm_bindgen(start)]
fn main() {
    let eg = EventGraph::new();
    eg.event(|pc| {
        let document = new_prim(pc, None);
        let signature = new_prim(pc, None);
        let list = new_vec(pc, vec![]);
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
                            file_button(document).classes(&["document"]).push(icon("document")),
                            file_button(signature).classes(&["stamp"]).push(icon("stamp")),
                            main_button(),
                            main_button()
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
