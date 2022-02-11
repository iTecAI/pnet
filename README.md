# pnet

Continuation of previous p2p network projects

## Packet Format

`{network id}|{packet type (any of [adv, msg, rsp, err])}|{message content}|{public key}|END`

## Node Types

### Basic Node

```
Node(
    :name Unique name within network - Should not use | or @
    :network_id ID of network to listen to - Should not use |
    :onmessage Callback to run when a message is recieved. Takes one argument
    :crypt Crypt object or None. If None, auto-generates object.
    :network_key Fernet encryption key of network. Leaving as None will disable network-level encryption
    :server_port Port to listen on
    :advertise_port Port to advertise on. Should be shared across a network
    :broadcast_interval Time between UDP advertisements
    :bind_ip IP to bind to
)
```

**Methods**:

-   `.serve()` - Starts server in another thread
-   `.shutdown()` - Stops server
-   `.send(target: name of target peer, data: arbitrary data)` - Send data to node

**Notes:**

-   Probably don't use this, it's extremely raw
-   Make sure you use encryption
-   `onmessage` should be a function that takes 1 argument

### Advanced Node

```
Node(
    :name Unique name within network - Should not use | or @
    :network_id ID of network to listen to - Should not use |
    :crypt Crypt object or None. If None, auto-generates object.
    :network_key Fernet encryption key of network. Leaving as None will disable network-level encryption
    :server_port Port to listen on
    :advertise_port Port to advertise on. Should be shared across a network
    :broadcast_interval Time between UDP advertisements
    :bind_ip IP to bind to
    :chunk_size Size of chunks in transmissions. Default 16KB should be fine
    :functions Dictionary of function name: function
)
```

**Methods**:

-   `@.register(function_name: name of function)` - Decorate functions with this to register them in the node. They should take 3 arguments:
    -   Node instance
    -   Originator node name
    -   A readable stream

The function should then return a readable stream.

-   `.send()` - Replaces `Node.send`

```
.send(
    target: either a target peer name, "*" for all known peers, or a list of peer names)
    command: command name
    data: An open file object, readable stream, or bytes
```

-   All other `Node` methods

### CommandNode

```
Node(
    :name Unique name within network - Should not use | or @
    :network_id ID of network to listen to - Should not use |
    :crypt Crypt object or None. If None, auto-generates object.
    :network_key Fernet encryption key of network. Leaving as None will disable network-level encryption
    :server_port Port to listen on
    :advertise_port Port to advertise on. Should be shared across a network
    :broadcast_interval Time between UDP advertisements
    :bind_ip IP to bind to
    :chunk_size Size of chunks in transmissions. Default 16KB should be fine
    :functions Dictionary of function name: function
)
```

**Methods:**

-   `@.register(function_name: name of function)` - Decorate functions with this to register them in the node. They should be of the following form:
    `function(node: CommandNode, originator: str, *args, **kwargs) -> Any JSON Encodable`

-   Sending commands:

```python
node.target("target or * or [targets]").<function name>(*args, **kwargs)
```

**Notes:**

-   Nodes implement `get_funcs` and `get_peers` calls automatically. Good for determining network topology.
