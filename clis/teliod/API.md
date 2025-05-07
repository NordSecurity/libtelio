# QNAP Build

To build Teliod package for QNAP devices there are two alternatives:

- Run cargo build directly:
```cargo build --verbose --target x86_64-unknown-linux-musl --package teliod --features qnap``` 

- Run build script [Recommended]:
```../../ci/build_libtelio.py build qnap x86_64 [--debug]```

The build script has an additional stage at the end of the build where it creates the QNAP package.

## REST API

This REST API allows interaction with the Teliod daemon. It provides endpoints for managing the daemon, updating its configuration, and retrieving logs and status information.

### Endpoints

#### 1. **Start the Daemon**
- **Endpoint**: `/`
- **Method**: `POST`
- **Description**: Starts the Teliod Daemon in the background.
- **Request Body**: None
- **Responses**:
  - **201 OK**: Daemon started successfully.
  - **400 Bad Request**: Daemon is already running.
  - **500 Internal Server Error**: Failed to start the daemon.

#### 2. **Stop the Daemon**
- **Endpoint**: `/`
- **Method**: `DELETE`
- **Description**: Stops the running Teliod Daemon.
- **Request Body**: None
- **Responses**:
  - **200 OK**: Daemon stopped successfully.
  - **410 Bad Request**: Daemon is not running.

#### 3. **Update Configuration**
- **Endpoint**: `/`
- **Method**: `PATCH`
- **Description**: Updates the daemon configuration with provided settings.
- **Request Body**: JSON object containing the configuration updates. Only specified fields will be updated; others remain unchanged.
- **Example Request Body**:
  ```json
  {
    "log_level": "info",
    "log_file_path": "/new/path/to/log.log"
  }
  ```
  - **Responses**:
  - **200 OK**: Configuration updated successfully
  - **400 Bad Request**: Invalid JSON payload or configuration fields.
  - **500 Internal Server Error**: Failed to update configuration.

#### 4. **Get Meshnet Status**
- **Endpoint**: `/?info=get-status`
- **Method**: `GET`
- **Description**: Retrieves the current status of the Meshnet from Teliod daemon.
- **Request Body**: None
- **Responses**:
  - **200 OK**: Status information in JSON format.
    ```json
    {
        "telio_is_running": true,
        "meshnet_ip": null,
        "external_nodes": []
        ...
    }
    ```
  - **500 Internal Server Error**: Failed to retrieve status (Bad daemon response).
  - **410 Gone**: Failed to communicate with the daemon (Couldn't send command/Daemon not accessible).
  - **502 Gateway Timeout**: Failed to communicate with the daemon (Timeout while waiting daemon).

#### 5. **Get Logs**
- **Endpoint**: `/?info=get-logs`
- **Method**: `GET`
- **Description**: Retrieves the latest logs of the Teliod Daemon.
Optional `days_count` parameter to specify a custom number of past day's
logs to return. For example `/get-logs?days_count=5` will return the logs
from the past 5 days if present.
- **Request Body**: None
- **Responses**:
  - **200 OK**: Log content in text format.
    ```
    {
        "Log line 1\nLog line 2\nLog line 3\n..."
    }
    ```
  - **500 Internal Server Error **: Error reading log file.

### Error Handling

For all endpoints, the following error codes may be returned:
- **400 Bad Request**: The request was malformed or invalid.
- **404 Not Found**: Uri path is invalid.

### Example usage with curl

#### Start Teliod daemon:
```bash
curl -X POST http://<NAS-IP>:8080/
```

#### Stop Teliod daemon:
```bash
curl -X DELETE http://<NAS-IP>:8080/
```

#### Get Teliod logs:
```bash
curl -X GET "http://<NAS-IP>:8080/?info=get-logs"
```

#### Update Config:
```bash
curl -X PATCH -H "Content-Type: application/json" -d '{"log_level":"info", authentication_token": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}' http://<NAS-IP>:8080/cgi-bin/qpkg/teliod.cgi
```
