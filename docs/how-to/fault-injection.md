# Simulate Network Chaos with FaultIo

This guide explains how to test retry classifiers, timeout thresholds, and streaming decoders under hostile transport conditions using in-process `FaultIo` fault injection.

---

## Overview of Fault Types

`FaultScript` schedules chaos faults keyed by the delivered byte offset:
- `Fault::Delay(Duration)`: Injects latency stalls before subsequent byte delivery.
- `Fault::Split { span, per_read }`: Slices reads into tiny micro-chunks to test frame fragmentation and buffer reassembly.
- `Fault::Truncate`: Emits premature EOF mid-stream to simulate dead gateways.
- `Fault::Reset`: Injects a TCP `ConnectionReset` error at a specific byte offset.

---

## Inject Delays and Micro-Splits

Wrap any asynchronous stream with `FaultIo` and a configured `FaultScript`:

```rust
use std::sync::{Arc, Mutex};
use std::time::Duration;
use netune::{Fault, FaultIo, FaultScript};
use tokio::io::{AsyncReadExt, duplex};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (mut writer, reader) = duplex(1024);

    // Schedule: 
    // 1. Stall for 100ms at byte 0
    // 2. Deliver only 4 bytes per read for the next 16 bytes
    // 3. Reset the connection at byte 32
    let script = FaultScript::new(vec![
        (0, Fault::Delay(Duration::from_millis(100))),
        (0, Fault::Split { span: 16, per_read: 4 }),
        (32, Fault::Reset),
    ]);

    let mut faulted_stream = FaultIo::new(reader, Arc::new(Mutex::new(script)));

    tokio::spawn(async move {
        let payload = b"0123456789abcdef0123456789abcdef0123456789";
        tokio::io::AsyncWriteExt::write_all(&mut writer, payload).await.unwrap();
    });

    let mut buf = [0u8; 64];
    loop {
        match faulted_stream.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => println!("Read chunk: {} bytes", n),
            Err(e) => {
                println!("Observed injected fault: {}", e);
                break;
            }
        }
    }

    Ok(())
}
```

---

## Clean Passthrough Verification

An empty `FaultScript` introduces zero side effects: every read and write passes through without overhead or memory allocation.
