### Natlab Guidelines:

1. **Use Parametrization:**
   - Test across all operating systems when possible.
   - Ensure parametrization for each node.

   **Why:**
   - Covers more areas.
   - Better readability.
   - Wider usage of a test.

   **Example:**
   ```
   @pytest.mark.parametrize("alpha_node", [ConnectionTag.VM_MAC, ConnectionTag.WINDOWS_VM, ConnectionTag.DOCKER_CONE_CLIENT_1])
   @pytest.mark.parametrize("beta_node", ConnectionTag.VM_MAC)
   def test_params(alpha_node, beta_node):
   ```

2. **Assertions Clarity:**
   - Assertions must be explicit and easily visible in the test.
   - Avoid assertions in different tasks, keep it within test, raise an exception instead if needed.

   **Why:**
   - Easier to track which test asserted if assert is within a test.
   - Easier to read stacktrace.

3. **Start Event Checks Promptly:**
   - Initiate event checks before the corresponding action begins.

   **Why:**
   - Starting to wait for event after action, might result in missing the event.

   **Example**:
   - DON'T:
   ```
      await connect_to_vpn()
      # event might occur event before starting to wait
      await wait_for_event_peer(State.Connected)
   ```
   - DO:
   ```
      async with asyncio_util.run_async_context(wait_for_event_peer(State.Connected)) as event:
            await asyncio.wait_for(
                asyncio.gather(
                    *[
                        connect_to_vpn()
                        event,
                    ]
                ),
                timeout
            )
   ```

4. **Utilize Provided Helpers:**
   - Employ provided helper functions to establish the test environment (helpers.py and etc.).

5. **Timeouts for Potential Hangs:**
   - Apply timeouts to actions susceptible to hanging.

   **Example:**
   - As previously mentioned, event might occur before starting to wait for it. To avoid natlab hanging, wrap coroutine or future to complete with timeout.
   ```
      await connect_to_vpn()
      await asyncio.wait_for(wait_for_event_peer(State.Connected), timeout=5)
   ```

6. **VM/Docker Reversion:**
   - Ensure any modifications to VM/Docker are reverted during test teardown.
   - Tests should leave no residual configurations even in case of failure.

   **Why:**
   - Some tests tinker with iptables / routing tables and some other significant stuff, which might lead to failure of other tests if not properly cleaned.

   **Example**:
   - DON'T:
   ```
   def test_1():
      # for the purpose of example, break_tcp_conn_to_host is not context manager and doesnt have a proper cleanup

      await connect_to(DERP_1)

      async with asyncio_util.run_async_context(wait_for_event_peer(State.Disconnected)) as event:
            await asyncio.wait_for(
                asyncio.gather(
                    *[
                        break_tcp_conn_to_host(DERP_1)
                        event,
                    ]
                ),
                timeout
            )

   # this test will fail, because previous test didn't cleanup properly
   def test_2():
      async with asyncio_util.run_async_context(wait_for_event_peer(State.Connected)) as event:
            await asyncio.wait_for(
                asyncio.gather(
                    *[
                        connect_to(DERP_1)
                        event,
                    ]
                ),
                timeout
            )
   ```

   - DO:
   ```
   @contextmanager
   def tmp_break_conn()
      try:
         break_tcp_conn_to_host(DERP_1)
         yield
      finally:
         restore_tcp_conn_to_host(DERP_1)


   def test():
      await connect_to(DERP_1)
      async with asyncio_util.run_async_context(wait_for_event_peer(State.Disconnected)) as event:
         with tmp_break_conn():
            await asyncio.wait_for(event, timeout)
   ```

7. **Confirmation Beyond stdout:**
   - Do not rely solely on stdout; explore alternative methods to confirm states using external tools.

   **Why:**:
   - Stdout might say "Connected", but there are no actual connection in conntrack records.

   **Example:**
   - Use connection tracker. Providing configuration to environment setup will enable it. When test being teardown, it will be checked, wether actual connection to vpn server was made.
   ```
   def test_connection():
      env = setup_env(SetupParams(connection_tag=ConnectionTag.DOCKER_CONE_CLIENT_1, connection_tracker_config=generate_connection_tracker_config(vpn_1_limits=ConnectionLimits(1, 1))))
      client.connect_to_vpn()
      client.wait_for_peer_state(Connected)
      assert "Connected" in client.get_stdout()
   ```

8. **Comprehensive Node State Checking:**
   - Examine the states of all related nodes, not just a single one.

   **Why:**
   - By checking only one node, it is not made sure, that other node will be the same.

   **Example:**  
   To check if two nodes are connected via meshnet PING is used.
   - DO:
   ```
   def test_meshnet(alpha, beta):
      env = setup_env([alpha, beta])
      verify_connectivity_between_nodes([alpha, beta])
      # assume that both peers are available
   ```
   - DON'T, because one of the node, might be blocking other node in firewall and by being able to ping from one side, you can't assume that connection is available both ways:
   ```
   def test_meshnet(alpha, beta):
      env = setup_env([alpha, beta])

      async with Ping(alpha, beta.ip).run() as ping:
         await ping.wait_for_next_ping()

      # assume that both peers are available
   ```
   because, this might have been the actual configuraton:
   ```
      alpha.set_peer_firewall_settings(beta, False)
      beta.set_peer_firewall_settings(alpha, True)
   ```

9. **Replace Sleep with Event Checks:**
   - Substitute sleep commands with event checks for enhanced reliability.

   **Example:**  
   Starting listening with `netcat`:
   - DON'T:
   ```
   await connection_alpha.create_process("nc -nluv -4 100.64.0.100 12345")
   await asyncio.sleep(2)
   # assume that listening started
   ```

   - DO:
   ```
   output_notifier = OutputNotifier()
   listening_start_event = asyncio.Event()
   process = connection_alpha.create_process("nc -nluv -4 100.64.0.100 12345", on_stdout = output_notifier.handle_output())
   output_notifier.notify_output(f"Bound on 100.64.0.100 12345", listening_start_event)
   await process.execute()
   await listening_start_event.wait()

   # listening started for sure
   ```

10. **Prefer Wrapper Classes:**
    - Opt for wrapper classes when interacting with external tools (e.g. derp_cli.py; ping.py; iperf3.py; stun.py and etc.).

    **Why:**
    - Improved encapsulation
    - Maintainability
    - Uniformity
    - Multiple OS support

