contract C {
    function f() public pure {
        bytes32 h = keccak256(abi.encodePacked(keccak256, f, blockhash));
        h;
    }
}
// ----
// TypeError: (91-100): This type cannot be encoded.
// TypeError: (102-103): This type cannot be encoded.
// TypeError: (105-114): This type cannot be encoded.
