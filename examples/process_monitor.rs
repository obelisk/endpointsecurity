#[macro_use] extern crate log;

use endpointsecurity::*;
use std::sync::mpsc::channel;

fn main() {
    env_logger::init();
    info!("Starting example process monitor");
    let (es_message_tx, es_message_rx) = channel();

    let client = match create_es_client(es_message_tx.clone()) {
        Ok(client) => client,
        Err(e) => {
            error!("{:?}: {}", e.error_type, e.details);
            return;
        }
    };

    if !client.set_subscriptions_to(&vec![SupportedEsEvent::NotifyExec, SupportedEsEvent::NotifyFork]) {
        error!("Could not subscribe to NotifyExec event (not sure why)");
        return;
    }

    loop {
        let message = match es_message_rx.recv() {
            Ok(v) => v,
            Err(e) => {
                error!("Error receiving new event but will continue anyway: {}", e);
                continue;
            }
        };

        match &message.event {
            EsEvent::NotifyExec(event) => {
                println!("Type: Exec, PID: {}, Path: {}, CDHash: {}, Args: {}", event.target.pid, event.target.executable.path, event.target.cdhash, event.args.join(" "));
            },
            EsEvent::NotifyFork(event) => {
                println!("Type: Fork, PID: {}, Path: {}, CDHash: {}", event.child.pid, event.child.executable.path, event.child.cdhash);
            },
            _ => {
                continue;
            }
        }
    }
}