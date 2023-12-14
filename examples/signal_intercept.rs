#[macro_use]
extern crate log;

use crossbeam_channel::unbounded as channel;
use endpointsecurity::*;

fn main() {
    env_logger::init();
    info!("Starting example signal intercept handler");

    let (es_message_tx, es_message_rx) = channel();

    let client = match create_es_client(es_message_tx.clone()) {
        Ok(client) => client,
        Err(e) => {
            error!("{:?}: {}", e.error_type, e.details);
            return;
        }
    };

    if !client.set_subscriptions_to(&vec![SupportedEsEvent::AuthSignal]) {
        error!("Could not subscribe to AuthSignal event (not sure why)");
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

        // We don't cache the result here for demonstation purposes. In practice you should
        // cache whenever possible but here we don't so you can see every denial instead of
        // just the first one
        match &message.event {
            EsEvent::AuthSignal(event) => {
                // Backout of all signals that don't affect EsClients as quickly as possible
                // to reduce impact to system responsiveness
                if !event.target.is_es_client {
                    client.respond_to_auth_event(
                        &message,
                        &EsAuthResult::Allow,
                        &EsCacheResult::No,
                    );
                    continue;
                }

                // My signing ID, don't let signals reach my EsClients
                if event.target.team_id == "5QYJ6C8ZNT" {
                    println!("Received a signal to my EsClient, disallowing that!");
                    client.respond_to_auth_event(&message, &EsAuthResult::Deny, &EsCacheResult::No);
                }

                // This is a signal to someone else's EsClient. Don't touch it
                client.respond_to_auth_event(&message, &EsAuthResult::Allow, &EsCacheResult::No);
            }
            _ => {
                continue;
            }
        }
    }
}
