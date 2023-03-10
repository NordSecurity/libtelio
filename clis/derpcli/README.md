# How to - Derpcli

## Derpcli interface

```
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
    -f, --config <path>            Path to config file
    -o, --output <output>          Path to logs output file [default: ""]
```

## Derpcli for large scale testing

### Providing config file
**Example**  
```
derpcli -f config.json -o output -vv
```

### Config file
```
{
    "clients": [
        {
            // clients private key
            "private_key": "IDv2SVTGIHar8c1zYEAHf8wQQwvSNZct9bRzSSYiA0Q=",

            // derp server
            "derp_server": "http://10.0.10.1:8765",

            // peers private key list
            "peers": [
                "qP2k8RKIAPFS0LAoA1MDQidOxImcYwGCsUqvmMqL21A="
            ],

            // period (ms)
            "period": 1000
        }
    ]
}
```

- Running multiple clients on one instance.

    **Example**  
        Running following config will create multiple clients on one instance. Clients will be pinging all of their peers. Config file:
    ```
    {
        "clients": [
            {
                // clients private key
                "private_key": "IDv2SVTGIHar8c1zYEAHf8wQQwvSNZct9bRzSSYiA0Q=",

                // derp server
                "derp_server": "http://10.0.10.1:8765",

                // peers private key list
                "peers": [
                    "qP2k8RKIAPFS0LAoA1MDQidOxImcYwGCsUqvmMqL21A="
                ],

                // period (ms)
                "period": 1000
            },
            {
                // clients private key
                "private_key": "qP2k8RKIAPFS0LAoA1MDQidOxImcYwGCsUqvmMqL21A=",

                // derp server
                "derp_server": "http://10.0.10.1:8765",

                // peers private key list
                "peers": [
                    "IDv2SVTGIHar8c1zYEAHf8wQQwvSNZct9bRzSSYiA0Q="
                ],

                // period (ms)
                "period": 200
            }
        ]
    }
    ```
- Running clients on different instances
    **Example**  
        Run following configs on different instances. Clients will be pinging all of their peers. Config files:
    **Config1.json**
    ```
    {
        "clients": [
            {
                // clients private key
                "private_key": "IDv2SVTGIHar8c1zYEAHf8wQQwvSNZct9bRzSSYiA0Q=",

                // derp server
                "derp_server": "http://10.0.10.1:8765",

                // peers private key list
                "peers": [
                    "qP2k8RKIAPFS0LAoA1MDQidOxImcYwGCsUqvmMqL21A="
                ],

                // period (ms)
                "period": 1000
            }
        ]
    }
    ```  
    **Config2.json**
    ```
    {
        "clients": [
            {
                // clients private key
                "private_key": "qP2k8RKIAPFS0LAoA1MDQidOxImcYwGCsUqvmMqL21A=",

                // derp server
                "derp_server": "http://10.0.10.1:8765",

                // peers private key list
                "peers": [
                    "IDv2SVTGIHar8c1zYEAHf8wQQwvSNZct9bRzSSYiA0Q="
                ],

                // period (ms)
                "period": 200
            }
        ]
    }
    ```

    ### Output file
    Running first example (multiple clients on one instance) will provide the following output file.
    **output**
    ```
    # HELP ping_counter client uVDathXVXVe5+HuGZMyUziuykj47m9ooLgOcwAg6wVE= peer 6/3sTTnOkWLb3TTk4CEcGldlZC83fEGbW0qMqTOF+hg= ping_counter
    # TYPE ping_counter counter
    ping_counter 7
    # HELP pong_counter client uVDathXVXVe5+HuGZMyUziuykj47m9ooLgOcwAg6wVE= peer 6/3sTTnOkWLb3TTk4CEcGldlZC83fEGbW0qMqTOF+hg= pong_counter
    # TYPE pong_counter counter
    pong_counter 7
    # HELP rtt client uVDathXVXVe5+HuGZMyUziuykj47m9ooLgOcwAg6wVE= peer 6/3sTTnOkWLb3TTk4CEcGldlZC83fEGbW0qMqTOF+hg= last ping pong round trip time (ms)
    # TYPE rtt gauge
    rtt 1
    # HELP ping_counter client 6/3sTTnOkWLb3TTk4CEcGldlZC83fEGbW0qMqTOF+hg= peer uVDathXVXVe5+HuGZMyUziuykj47m9ooLgOcwAg6wVE= ping_counter
    # TYPE ping_counter counter
    ping_counter 35
    # HELP pong_counter client 6/3sTTnOkWLb3TTk4CEcGldlZC83fEGbW0qMqTOF+hg= peer uVDathXVXVe5+HuGZMyUziuykj47m9ooLgOcwAg6wVE= pong_counter
    # TYPE pong_counter counter
    pong_counter 35
    # HELP rtt client 6/3sTTnOkWLb3TTk4CEcGldlZC83fEGbW0qMqTOF+hg= peer uVDathXVXVe5+HuGZMyUziuykj47m9ooLgOcwAg6wVE= last ping pong round trip time (ms)
    # TYPE rtt gauge
    rtt 2

    ```