'''Deserializer for Veil transaction types'''

from collections import namedtuple

from electrumx.lib.hash import sha256, double_sha256, hash_to_hex_str

from electrumx.lib.tx import Deserializer
from electrumx.lib.util import (pack_le_uint16, pack_le_int32, pack_le_uint32,
                                pack_le_int64, pack_varint, pack_varbytes,
                                pack_be_uint16)

class TxInputVeil(namedtuple("TxInput", "prev_hash prev_idx tree sequence")):
    '''Class representing a Veil transaction input.'''

    def __str__(self):
        prev_hash = hash_to_hex_str(self.prev_hash)
        return ("Input({}, {:d}, tree={}, sequence={:d})"
                .format(prev_hash, self.prev_idx, self.tree, self.sequence))

    def is_generation(self):
        '''Test if an input is generation/coinbase like'''
        return self.prev_idx == MINUS_1 and self.prev_hash == ZERO


class TxOutputVeil(namedtuple("TxOutput", "value version pk_script")):
    '''Class representing a Veil transaction output.'''


class TxVeil(namedtuple("Tx", "version inputs outputs locktime")):
    '''Class representing a Veil  transaction.'''


class DeserializerVeil(Deserializer):
    def read_tx(self):
        return self._read_tx_parts(produce_hash=False)[0]

    def read_tx_and_hash(self):
        tx, tx_hash, _vsize = self._read_tx_parts()
        return tx, tx_hash

    def read_tx_and_vsize(self):
        tx, _tx_hash, vsize = self._read_tx_parts(produce_hash=False)
        return tx, vsize

    def read_tx_block(self):
        '''Returns a list of (deserialized_tx, tx_hash) pairs.'''
        read = self.read_tx_and_hash
        txs = [read() for _ in range(self._read_varint())]
        return txs

    def read_tx_tree(self):
        '''Returns a list of deserialized_tx without tx hashes.'''
        read_tx = self.read_tx
        return [read_tx() for _ in range(self._read_varint())]

    def _read_input(self):
        return TxInputVeil(
            self._read_nbytes(32),   # prev_hash
            self._read_le_uint32(),  # prev_idx
            self._read_byte(),       # tree
            self._read_le_uint32(),  # sequence
        )

    def _read_output(self):
        return TxOutputVeil(
            self._read_le_int64(),  # value
            self._read_le_uint16(),  # version
            self._read_varbytes(),  # pk_script
        )

    def _read_tx_parts(self, produce_hash=True):
        start = self.cursor
        version = self._read_le_int32()
        inputs = self._read_inputs()
        outputs = self._read_outputs()
        locktime = self._read_le_uint32()
        end_prefix = self.cursor

        if produce_hash:
            prefix_tx = self.binary[start+4:end_prefix]
            tx_hash = double_sha256(prefix_tx)
        else:
            tx_hash = None

        return TxVeil(
            version,
            inputs,
            outputs,
            locktime,
        ), tx_hash, self.cursor - start
