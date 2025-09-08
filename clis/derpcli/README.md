# How to - Derpcli

## Derpcli interface

```bash
run derpcli -h for usage help

DERP cli
Command line utility to perform DERP tests

USAGE:
    derpcli [FLAGS] [OPTIONS]

FLAGS:
    -h, --help       Prints help information
    -l, --loop       Loop until interrupted
    -t, --target     Run as target
    -V, --version    Prints version information
    -v, --verbose    Verbose output (can use multiple)

OPTIONS:
    -c, --count <count>            Count of iterations to run [default: 3]
    -a, --data <data>              Data text to send, <to be implemented> [default: hello derp!]
    -d, --delay <delay>            Delay ms between iterations [default: 100]
    -m, --mykey <mykey>            My private key base64 encoded
    -s, --server <server>          Server address [default: http://localhost:1234]
    -z, --size <size>              Data text size to generate and send
    -k, --targetkey <targetkey>    Target peer private key base64 encoded
    -C, --CA <path>                Path to CA.pem file [default: ""]
    -f, --config <path>            Path to config file
```

## Derpcli for large scale testing

### Providing config file

**Example**  

``` shell
derpcli --config config.json -C ca.pem -vv
```

### Config file

Clients are created in pairs on the same instance of `derpcli`. Client count
should be even (if no error occured). Timestamp and first DERP name is put
into payload to measure RTT routed to some DERP. Clients can be assigned
to different DERP servers, by manipulating `derp1_increment` and `derp2_offset`.
The first DERP NR for the first client is always NR 0. On every next client pair
assign for one client the next DERP will be selected by incrementing prev NR by
`derp1_increment`. Second client DERP is chosen by `derp2_offset` from first
client.

The following config will assign pair clients to the same DERP.

``` json
{
  "client_count": 4,
  "interval_min": 1000,
  "interval_max": 2000,
  "payload_min": 128,
  "payload_max": 386,
  "client1_pinger": true,
  "client2_pinger": false,
  "derp1_increment": 1,
  "derp2_offset": 0,
  "derps": [
    "https://derp-a:8765",
    "https://derp-b:8765"
  ],
  "stats_take_every": 1
}
```

### Output

  ```log
[2023-02-24 13:28:05]  Clients: 0, GOAL: 4
* Adding 2 client pairs
* Resolving derp-a:8765
* Resolving derp-b:8765
DERPS resolved: [[10.0.10.1:8765], [10.0.10.2:8765]]
* Adding clients => 4
* [RD0R] -> TX START
* [RD0R] -> RX START
* [DQeL] -> TX START
* [DQeL] -> RX START
* [RD0R] -> Send 357b via [derp-a] to [DQeL], after 0.000s
* [kbcB] -> TX START
* [kbcB] -> RX START
* [kbcB] -> Send 249b via [derp-b] to [f3Fo], after 0.000s
* [DQeL] -> Recv 357b from [RD0R], RTT: 99ms
* [f3Fo] -> TX START
* [f3Fo] -> RX START
* [kbcB] -> Send 202b via [derp-b] to [f3Fo], after 1.217s
* [f3Fo] -> Recv 202b from [kbcB], RTT: 93ms
* [RD0R] -> Send 245b via [derp-a] to [DQeL], after 1.867s
* [DQeL] -> Recv 245b from [RD0R], RTT: 100ms

13:28:07 Clients: 4
* Avg. RTT via [derp-b]: 93.00 ms
* Avg. RTT via [derp-a]: 99.50 ms

* [kbcB] -> Send 330b via [derp-b] to [f3Fo], after 1.171s
* [f3Fo] -> Recv 330b from [kbcB], RTT: 113ms
* [RD0R] -> Send 292b via [derp-a] to [DQeL], after 1.649s
* [DQeL] -> Recv 292b from [RD0R], RTT: 91ms

13:28:09 Clients: 4
* Avg. RTT via [derp-a]: 95.50 ms
* Avg. RTT via [derp-b]: 103.00 ms

* [kbcB] -> Send 219b via [derp-b] to [f3Fo], after 1.756s
* [f3Fo] -> Recv 219b from [kbcB], RTT: 203ms
* [RD0R] -> Send 239b via [derp-a] to [DQeL], after 1.897s
* [DQeL] -> Recv 239b from [RD0R], RTT: 93ms
* [kbcB] -> Send 364b via [derp-b] to [f3Fo], after 1.729s
* [f3Fo] -> Recv 364b from [kbcB], RTT: 93ms

13:28:11 Clients: 4
* Avg. RTT via [derp-a]: 92.00 ms
* Avg. RTT via [derp-b]: 148.00 ms

  ```
