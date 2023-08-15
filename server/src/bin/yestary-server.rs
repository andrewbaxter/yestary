use std::{
    sync::Arc,
    io,
};
use aargvark::vark;
use chrono::Utc;
use loga::{
    ea,
    Log,
    fatal,
    ResultContext,
};
use openpgp_card_pcsc::PcscBackend;
use openpgp_card_sequoia::{
    Card,
    state::Open,
};
use poem::{
    Server,
    listener::TcpListener,
    Route,
    endpoint::{
        StaticFilesEndpoint,
    },
    web::{
        Data,
        Path,
    },
    Response,
    http::StatusCode,
    middleware::AddData,
    get,
    handler,
    IntoResponse,
    EndpointExt,
};
use sequoia_openpgp::{
    serialize::stream::{
        Armorer,
        LiteralWriter,
        Message,
        Signer,
    },
};
use shared::SerialStamp;
use tokio::select;

mod args {
    use std::{
        net::{
            SocketAddr,
        },
        path::PathBuf,
    };
    use aargvark::{
        Aargvark,
        AargvarkJson,
    };
    use serde::{
        Serialize,
        Deserialize,
    };

    #[derive(Serialize, Deserialize)]
    pub struct Config {
        pub web_bind_addr: SocketAddr,
        pub keys_dir: PathBuf,
        pub static_dir: PathBuf,
    }

    #[derive(Aargvark)]
    pub struct Args {
        pub config: AargvarkJson<Config>,
    }
}

#[tokio::main]
async fn main() {
    async fn inner() -> Result<(), loga::Error> {
        let config = vark::<args::Args>().config.value;
        let log = &loga::new(loga::Level::Info);
        let tm = taskmanager::TaskManager::new();

        // App + api server
        tm.critical_task({
            let log = log.fork(ea!(sys = "web"));
            let tm = tm.clone();

            struct Inner {
                log: Log,
            }

            let inner = Arc::new(Inner { log: log.clone() });
            async move {
                let server =
                    Server::new(
                        TcpListener::bind(config.web_bind_addr),
                    ).run(
                        Route::new()
                            .nest(
                                "/api",
                                Route::new()
                                    .nest("key", StaticFilesEndpoint::new(&config.keys_dir))
                                    .at("stamp/:hash", get({
                                        #[handler]
                                        async fn ep(Data(service): Data<&Arc<Inner>>, Path(hash): Path<String>) -> Response {
                                            match async move {
                                                let mut card: Card<Open> =
                                                    PcscBackend::cards(None)
                                                        .context("Error listing cards")?
                                                        .into_iter()
                                                        .next()
                                                        .ok_or_else(|| loga::err("No pcsc cards detected"))?
                                                        .into();
                                                let mut transaction =
                                                    card
                                                        .transaction()
                                                        .log_context(
                                                            &service.log,
                                                            "Failed to start card transaction",
                                                        )?;
                                                let card_id =
                                                    transaction
                                                        .application_identifier()
                                                        .log_context(&service.log, "Error getting gpg id of card")?
                                                        .ident();
                                                transaction
                                                    .verify_user_for_signing("123456".as_bytes())
                                                    .log_context_with(
                                                        &service.log,
                                                        "Error unlocking card with pin",
                                                        ea!(card = card_id),
                                                    )?;
                                                let signer_interact = || panic!("Card requires interaction");
                                                let mut signer0 = transaction.signing_card().unwrap();
                                                let mut signer =
                                                    signer0
                                                        .signer(&signer_interact)
                                                        .log_context(&service.log, "Failed to get signer from card")?;
                                                let mut sink = vec![];
                                                let mut message =
                                                    LiteralWriter::new(
                                                        Signer::new(
                                                            Armorer::new(Message::new(&mut sink))
                                                                .build()
                                                                .map_err(
                                                                    |e| loga::err_with(
                                                                        "Failed to create armored message builder",
                                                                        ea!(err = e.to_string()),
                                                                    ),
                                                                )?,
                                                            signer,
                                                        )
                                                            .build()
                                                            .map_err(
                                                                |e| loga::err_with(
                                                                    "Failed to create signer serializer",
                                                                    ea!(err = e.to_string()),
                                                                ),
                                                            )?,
                                                    )
                                                        .build()
                                                        .map_err(
                                                            |e| loga::err_with(
                                                                "Failed to create literal writer",
                                                                ea!(err = e.to_string()),
                                                            ),
                                                        )?;
                                                io::copy(
                                                    &mut serde_json::to_vec(&SerialStamp {
                                                        hash: hash,
                                                        stamp: Utc::now(),
                                                    }).unwrap().as_slice(),
                                                    &mut message,
                                                ).context("Failed to sign data")?;
                                                message
                                                    .finalize()
                                                    .map_err(
                                                        |e| loga::err_with(
                                                            "Failed to write data",
                                                            ea!(err = e.to_string()),
                                                        ),
                                                    )?;
                                                return Ok(
                                                    Response
                                                    ::builder().body(
                                                        String::from_utf8(
                                                            sink,
                                                        ).context("Failed to convert armor into string")?,
                                                    ),
                                                );
                                            }.await {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    service.log.warn_e(e, "Error setting star", ea!());
                                                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                                },
                                            }
                                        }

                                        ep
                                    })),
                            )
                            .nest("/", StaticFilesEndpoint::new(&config.static_dir).index_file("index.html"))
                            .with(AddData::new(inner)),
                    );

                select!{
                    _ = tm.until_terminate() => {
                        return Ok(());
                    }
                    r = server => {
                        return r.log_context(&log, "Exited with error");
                    }
                }
            }
        });

        // Wait for shutdown, cleanup
        tm.join().await?;
        return Ok(());
    }

    match inner().await {
        Ok(_) => { },
        Err(e) => {
            fatal(e);
        },
    }
}
