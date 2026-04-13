/*
 *
 * Transactions (Updated)
 *
 */

const utils = require('./utils');

////////////////////////////////////////////////////////////////////////////////

// Main Transactions Function
const Transactions = function() {

  // Split daemon-built coinbasetxn into [p1, p2] for extranonce injection.
  // Used when useCoinbasetxn is set and the mining algo needs extranonce
  // variation in the scriptSig (x11/default path). For equihash and kawpow,
  // miners vary the header nonce so extranonce injection is unnecessary --
  // the caller should use getCoinbasetxnRaw() instead.
  //
  // Parses the raw coinbasetxn to find the scriptSig, locates the height
  // push at its start, and splits there. p1 = everything up to and
  // including the height serialization. p2 = sequence + outputs + locktime
  // + optional extra payload. The gap between p1 and p2 is filled with
  // extranonce1 + extranonce2 at share time.
  this.splitCoinbasetxn = function(coinbasetxnHex, extraNoncePlaceholder) {
    const raw = Buffer.from(coinbasetxnHex, 'hex');
    let offset = 0;

    // version (4 bytes)
    offset += 4;

    // txin count (varint, always 1 for coinbase)
    offset += 1;

    // prevout hash (32 bytes, all zeros for coinbase)
    offset += 32;

    // prevout index (4 bytes, 0xffffffff)
    offset += 4;

    // scriptSig length (varint)
    const scriptSigLenByte = raw[offset];
    let scriptSigLenBytes = 1;
    let actualScriptSigLen = scriptSigLenByte;
    if (scriptSigLenByte === 0xfd) {
      actualScriptSigLen = raw.readUInt16LE(offset + 1);
      scriptSigLenBytes = 3;
    } else if (scriptSigLenByte === 0xfe) {
      actualScriptSigLen = raw.readUInt32LE(offset + 1);
      scriptSigLenBytes = 5;
    }
    const scriptSigStart = offset + scriptSigLenBytes;
    offset = scriptSigStart;

    // Height push: [pushlen] [height bytes LE]
    const heightPushLen = raw[offset];
    const heightEnd = offset + 1 + heightPushLen;
    const scriptSigEnd = scriptSigStart + actualScriptSigLen;

    // Rewrite scriptSig length: height push + extranonce placeholder
    const extraNonceLen = extraNoncePlaceholder.length;
    const newScriptSigLen = (heightEnd - scriptSigStart) + extraNonceLen;

    let newLenBuf;
    if (newScriptSigLen < 0xfd) {
      newLenBuf = Buffer.from([newScriptSigLen]);
    } else if (newScriptSigLen <= 0xffff) {
      newLenBuf = Buffer.alloc(3);
      newLenBuf[0] = 0xfd;
      newLenBuf.writeUInt16LE(newScriptSigLen, 1);
    } else {
      newLenBuf = Buffer.alloc(5);
      newLenBuf[0] = 0xfe;
      newLenBuf.writeUInt32LE(newScriptSigLen, 1);
    }

    // p1: version + txin_count + prevout + rewritten scriptSig len + height push
    const p1 = Buffer.concat([
      raw.slice(0, scriptSigStart - scriptSigLenBytes),
      newLenBuf,
      raw.slice(scriptSigStart, heightEnd),
    ]);

    // p2: sequence + outputs + locktime + optional extra payload
    const p2 = raw.slice(scriptSigEnd);

    return [p1, p2];
  };

  // Return the coinbasetxn as a single raw buffer. Used for equihash
  // and kawpow where the miner varies the header nonce instead of the
  // extranonce in the coinbase scriptSig.
  this.getCoinbasetxnRaw = function(coinbasetxnHex) {
    return Buffer.from(coinbasetxnHex, 'hex');
  };

  // Default Transaction Protocol
  this.default = function(poolConfig, rpcData, extraNoncePlaceholder, auxMerkle) {

    // Coinbasetxn bypass: daemon builds the coinbase, pool uses it as-is
    // or splits it for extranonce injection depending on mining algo.
    if (poolConfig.primary.coin.useCoinbasetxn && rpcData.coinbasetxn && rpcData.coinbasetxn.data) {
      const algo = poolConfig.primary.coin.algorithms.mining;
      if (algo === 'equihash' || algo === 'kawpow') {
        // No extranonce needed, miners vary header nonce.
        // Return [full_tx, empty] so serializeCoinbase still works:
        // Buffer.concat([generation[0], extraNonce1, generation[1]])
        // becomes just the raw coinbase (extraNonce1 is prepended but
        // we handle this in template.serializeCoinbase).
        const raw = this.getCoinbasetxnRaw(rpcData.coinbasetxn.data);
        return [raw, Buffer.alloc(0)];
      }
      // x11/default: split coinbasetxn for extranonce injection
      return this.splitCoinbasetxn(rpcData.coinbasetxn.data, extraNoncePlaceholder);
    }

    const txLockTime = 0;
    const txInSequence = 0;
    const txInPrevOutHash = '';
    const txInPrevOutIndex = Math.pow(2, 32) - 1;
    const txOutputBuffers = [];

    let txExtraPayload;
    let txVersion = poolConfig.primary.coin.version;
    const network = !poolConfig.settings.testnet ? poolConfig.primary.coin.mainnet : poolConfig.primary.coin.testnet;

    // Handle Version w/ CoinbaseTxn
    if (rpcData.coinbasetxn && rpcData.coinbasetxn.data) {
      txVersion = parseInt(utils.reverseHex(rpcData.coinbasetxn.data.slice(0, 8)), 16);
    }

    // Support Coinbase v3 Block Template
    if (rpcData.coinbase_payload && rpcData.coinbase_payload.length > 0) {
      txExtraPayload = Buffer.from(rpcData.coinbase_payload, 'hex');
      txVersion = txVersion + (5 << 16);
    }

    let reward = rpcData.coinbasevalue;
    let rewardToPool = reward;
    const coinbaseAux = rpcData.coinbaseaux.flags ? Buffer.from(rpcData.coinbaseaux.flags, 'hex') : Buffer.from([]);
    const poolAddressScript = utils.addressToScript(poolConfig.primary.address, network);

    // Handle Timestamp if Necessary
    const txTimestamp = poolConfig.primary.coin.hybrid === true ?
      utils.packUInt32LE(rpcData.curtime) :
      Buffer.from([]);

    let scriptSig = Buffer.concat([
      utils.serializeNumber(rpcData.height),
      coinbaseAux,
      utils.serializeNumber(Date.now() / 1000 | 0),
      Buffer.from([extraNoncePlaceholder.length]),
    ]);

    if (auxMerkle && poolConfig.auxiliary && poolConfig.auxiliary.enabled) {
      scriptSig = Buffer.concat([
        scriptSig,
        Buffer.from(poolConfig.auxiliary.coin.header, 'hex'),
        utils.reverseBuffer(auxMerkle.root),
        utils.packUInt32LE(auxMerkle.data.length),
        utils.packUInt32LE(0)
      ]);
    }

    // Build First Part of Generation Transaction
    const p1 = Buffer.concat([
      utils.packUInt32LE(txVersion),
      txTimestamp,
      utils.varIntBuffer(1),
      utils.uint256BufferFromHash(txInPrevOutHash),
      utils.packUInt32LE(txInPrevOutIndex),
      utils.varIntBuffer(scriptSig.length + extraNoncePlaceholder.length),
      scriptSig
    ]);

    // Handle Masternodes
    if (rpcData.masternode) {
      if (rpcData.masternode.payee) {
        const payeeReward = rpcData.masternode.amount;
        const payeeScript = utils.addressToScript(rpcData.masternode.payee, network);
        reward -= payeeReward;
        rewardToPool -= payeeReward;
        txOutputBuffers.push(Buffer.concat([
          utils.packUInt64LE(payeeReward),
          utils.varIntBuffer(payeeScript.length),
          payeeScript,
        ]));
      } else if (rpcData.masternode.length > 0) {
        rpcData.masternode.forEach(payee => {
          const payeeReward = payee.amount;
          let payeeScript;
          if (payee.script) {
            payeeScript = Buffer.from(payee.script, 'hex');
          } else {
            payeeScript = utils.addressToScript(payee.payee, network);
          }
          reward -= payeeReward;
          rewardToPool -= payeeReward;
          txOutputBuffers.push(Buffer.concat([
            utils.packUInt64LE(payeeReward),
            utils.varIntBuffer(payeeScript.length),
            payeeScript,
          ]));
        });
      }
    }

    // Handle Smartnodes
    if (rpcData.smartnode) {
      if (rpcData.smartnode.payee) {
        const payeeReward = rpcData.smartnode.amount;
        const payeeScript = utils.addressToScript(rpcData.smartnode.payee, network);
        reward -= payeeReward;
        rewardToPool -= payeeReward;
        txOutputBuffers.push(Buffer.concat([
          utils.packUInt64LE(payeeReward),
          utils.varIntBuffer(payeeScript.length),
          payeeScript,
        ]));
      } else if (rpcData.smartnode.length > 0) {
        rpcData.smartnode.forEach(payee => {
          const payeeReward = payee.amount;
          let payeeScript;
          if (payee.script) {
            payeeScript = Buffer.from(payee.script, 'hex');
          } else {
            payeeScript = utils.addressToScript(payee.payee, network);
          }
          reward -= payeeReward;
          rewardToPool -= payeeReward;
          txOutputBuffers.push(Buffer.concat([
            utils.packUInt64LE(payeeReward),
            utils.varIntBuffer(payeeScript.length),
            payeeScript,
          ]));
        });
      }
    }

    // Handle Superblocks
    if (rpcData.superblock && rpcData.superblock.length > 0) {
      rpcData.superblock.forEach(payee => {
        const payeeReward = payee.amount;
        let payeeScript;
        if (payee.script) {
          payeeScript = Buffer.from(payee.script, 'hex');
        } else {
          payeeScript = utils.addressToScript(payee.payee, network);
        }
        reward -= payeeReward;
        rewardToPool -= payeeReward;
        txOutputBuffers.push(Buffer.concat([
          utils.packUInt64LE(payeeReward),
          utils.varIntBuffer(payeeScript.length),
          payeeScript,
        ]));
      });
    }

    // Handle ZNodes (Evo Nodes)
    if (rpcData.znode_payments_started && rpcData.znode_payments_enforced) {
      rpcData.znode.forEach(payee => {
        const payeeReward = payee.amount;
        let payeeScript;
        if (payee.script) {
          payeeScript = Buffer.from(payee.script, 'hex');
        } else {
          payeeScript = utils.addressToScript(payee.payee, network);
        }
        // Block Reward Already Subtracts ZNode Rewards (FiroCoin)
        txOutputBuffers.push(Buffer.concat([
          utils.packUInt64LE(payeeReward),
          utils.varIntBuffer(payeeScript.length),
          payeeScript,
        ]));
      });
    }

    // Handle Other Given Payees
    if (rpcData.payee) {
      const payeeReward = rpcData.payee_amount || Math.ceil(reward / 5);
      const payeeScript = utils.addressToScript(rpcData.payee, network);
      reward -= payeeReward;
      rewardToPool -= payeeReward;
      txOutputBuffers.push(Buffer.concat([
        utils.packUInt64LE(payeeReward),
        utils.varIntBuffer(payeeScript.length),
        payeeScript,
      ]));
    }

    // Handle Secondary Transactions
    let founderReward, founderScript;
    switch (poolConfig.primary.coin.rewards.type) {

    // RTM-Based Transactions
    case 'raptoreum':
      if (rpcData.founder_payments_started && rpcData.founder) {
        founderReward = rpcData.founder.amount;
        founderScript = utils.addressToScript(rpcData.founder.payee, network);
        reward -= founderReward;
        rewardToPool -= founderReward;
        txOutputBuffers.push(Buffer.concat([
          utils.packUInt64LE(founderReward),
          utils.varIntBuffer(founderScript.length),
          founderScript,
        ]));
      }
      break;

    // FIRO-Based Transactions
    case 'firocoin':
      poolConfig.primary.coin.rewards.addresses.forEach((address) => {
        founderReward = address.amount;
        founderScript = utils.addressToScript(address.address, network);
        // Block Reward Already Subtracts Founder Rewards (FiroCoin)
        txOutputBuffers.push(Buffer.concat([
          utils.packUInt64LE(founderReward),
          utils.varIntBuffer(founderScript.length),
          founderScript,
        ]));
      });
      break;

    // HVQ-Based Transactions
    case 'hivecoin':
      founderReward = rpcData.CommunityAutonomousValue;
      founderScript = utils.addressToScript(rpcData.CommunityAutonomousAddress, network);
      txOutputBuffers.unshift(Buffer.concat([
        utils.packUInt64LE(founderReward),
        utils.varIntBuffer(founderScript.length),
        founderScript,
      ]));
      break;

    default:
      break;
    }

    // Handle Recipient Transactions
    let recipientTotal = 0;
    poolConfig.primary.recipients.forEach(recipient => {
      const recipientReward = Math.floor(recipient.percentage * reward);
      const recipientScript = utils.addressToScript(recipient.address, network);
      recipientTotal += recipientReward;
      txOutputBuffers.push(Buffer.concat([
        utils.packUInt64LE(recipientReward),
        utils.varIntBuffer(recipientScript.length),
        recipientScript,
      ]));
    });

    // Remove Recipient Percentages from Total
    reward -= recipientTotal;
    rewardToPool -= recipientTotal;

    // Handle Pool Transaction
    txOutputBuffers.unshift(Buffer.concat([
      utils.packUInt64LE(rewardToPool),
      utils.varIntBuffer(poolAddressScript.length),
      poolAddressScript
    ]));

    // Handle Witness Commitment
    if (rpcData.default_witness_commitment !== undefined) {
      const witness_commitment = Buffer.from(rpcData.default_witness_commitment, 'hex');
      txOutputBuffers.push(Buffer.concat([
        utils.packUInt64LE(0),
        utils.varIntBuffer(witness_commitment.length),
        witness_commitment
      ]));
    }

    // Combine Output Transactions
    const outputTransactions = Buffer.concat([
      utils.varIntBuffer(txOutputBuffers.length),
      Buffer.concat(txOutputBuffers)
    ]);

    // Build Second Part of Generation Transaction
    let p2 = Buffer.concat([
      utils.packUInt32LE(txInSequence),
      outputTransactions,
      utils.packUInt32LE(txLockTime),
    ]);

    // Check for Extra Transaction Payload
    if (txExtraPayload !== undefined) {
      p2 = Buffer.concat([
        p2,
        utils.varIntBuffer(txExtraPayload.length),
        txExtraPayload
      ]);
    }

    return [p1, p2];
  };
};

module.exports = Transactions;
