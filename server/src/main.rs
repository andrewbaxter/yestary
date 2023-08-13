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
                db: Pool,
            }

            let inner = Arc::new(Inner {
                log: log.clone(),
                db: db.clone(),
            });
            async move {
                let server =
                    Server::new(
                        TcpListener::bind(config.web_bind_addr),
                    ).run(
                        Route::new()
                            .nest(
                                "/api",
                                Route::new()
                                    .at("key/:key", StaticFilesEndpoint::new(&config.keys_dir))
                                    .at("d/:device/star/:time", post({
                                        #[handler]
                                        async fn ep(
                                            Data(service): Data<&Arc<Inner>>,
                                            Path((device, time)): Path<(String, MsUnit)>,
                                            Json(body): Json<String>,
                                        ) -> Response {
                                            match aes!({
                                                let mut db = service.db.get().await?;
                                                let new = tx(&mut **db, |mut txn| async {
                                                    let found =
                                                        txe!(
                                                            txn,
                                                            core_server::db::get_star(&mut txn, &device, time.0).await
                                                        ).is_some();
                                                    if found {
                                                        return (txn, Ok(false));
                                                    }
                                                    txe!(
                                                        txn,
                                                        core_server::db::insert_star(
                                                            &mut txn,
                                                            &device,
                                                            time.0,
                                                            &body,
                                                        ).await
                                                    );
                                                    return (txn, Ok(true));
                                                }).await?;
                                                if new {
                                                    process_star_change(&mut **db, &device, time, 1).await?;
                                                }
                                                return Ok(StatusCode::OK.into_response());
                                            }).await {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    service.log.warn_e(e, "Error setting star", ea!());
                                                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                                },
                                            }
                                        }

                                        ep
                                    }).delete({
                                        #[handler]
                                        async fn ep(Data(service): Data<&Arc<Inner>>, Path((device, time)): Path<(String, MsUnit)>) -> Response {
                                            match aes!({
                                                let mut db = service.db.get().await?;
                                                let deleted =
                                                    core_server::db::delete_star(&mut **db, &device, time.0).await?;
                                                if deleted.is_some() {
                                                    process_star_change(&mut **db, &device, time, -1).await?;
                                                }
                                                return Ok(StatusCode::OK.into_response());
                                            }).await {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    service.log.warn_e(e, "Error retrieving deleting star", ea!());
                                                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                                },
                                            }
                                        }

                                        ep
                                    }))
                                    .at("d/:device/star/:time/before", get({
                                        #[handler]
                                        async fn ep(Data(service): Data<&Arc<Inner>>, Path((device, time)): Path<(String, MsUnit)>) -> Response {
                                            match aes!({
                                                let mut db = service.db.get().await?;
                                                let stars =
                                                    core_server::db::get_stars_before(
                                                        &mut **db,
                                                        &device,
                                                        time.0,
                                                    ).await?;
                                                return Ok(Json(stars.into_iter().map(|s| app_req::Star {
                                                    time: MsUnit(s.time),
                                                    text: s.text,
                                                }).collect::<Vec<app_req::Star>>()).into_response());
                                            }).await {
                                                Ok(r) => r,
                                                Err(e) => {
                                                    service
                                                        .log
                                                        .warn_e(e, "Error retrieving stars before time", ea!());
                                                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                                                },
                                            }
                                        }

                                        ep
                                    })),
                            )
                            .nest("/", StaticFilesEndpoint::new(&config.static_dir))
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
