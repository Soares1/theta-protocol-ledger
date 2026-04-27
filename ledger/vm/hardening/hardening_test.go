package hardening

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thetatoken/theta/common"
	"github.com/thetatoken/theta/crypto"
	"github.com/thetatoken/theta/ledger/state"
	"github.com/thetatoken/theta/ledger/types"
	"github.com/thetatoken/theta/ledger/vm"
	"github.com/thetatoken/theta/store/database/backend"
)

// Logs emitted inside a reverted sub-call should not be kept in the StoreView
// after its frame is unwound.
func TestLogsDiscardedOnNestedRevert(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_a", types.NewCoins(90000000, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	innerAddr := common.HexToAddress("0x1000000000000000000000000000000000000001")
	outerAddr := common.HexToAddress("0x2000000000000000000000000000000000000002")

	// inner: LOG0; REVERT
	innerCode := []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x60, 0x00, 0x60, 0x00, 0xfd}

	// outer: CALL inner; POP; STOP
	outerCode := []byte{
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x73,
	}
	outerCode = append(outerCode, innerAddr.Bytes()...)
	outerCode = append(outerCode, 0x61, 0xff, 0xff, 0xf1, 0x50, 0x00)

	storeView.SetCode(innerAddr, innerCode)
	storeView.SetCode(outerAddr, outerCode)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: outerAddr},
		GasLimit: 200000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)
	assert.Equal(0, len(storeView.PopLogs()))
}

// Logs from a successful sibling sub-call should survive when a later
// sibling reverts.
func TestLogsKeptFromSuccessfulSiblingCall(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_b", types.NewCoins(90000000, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	successAddr := common.HexToAddress("0x3000000000000000000000000000000000000003")
	revertAddr := common.HexToAddress("0x4000000000000000000000000000000000000004")
	outerAddr := common.HexToAddress("0x5000000000000000000000000000000000000005")

	successCode := []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x00}
	revertCode := []byte{0x60, 0x00, 0x60, 0x00, 0xa0, 0x60, 0x00, 0x60, 0x00, 0xfd}

	buildCall := func(target common.Address) []byte {
		code := []byte{
			0x60, 0x00,
			0x60, 0x00,
			0x60, 0x00,
			0x60, 0x00,
			0x60, 0x00,
			0x73,
		}
		code = append(code, target.Bytes()...)
		code = append(code, 0x61, 0xff, 0xff, 0xf1, 0x50)
		return code
	}

	outerCode := append(buildCall(successAddr), buildCall(revertAddr)...)
	outerCode = append(outerCode, 0x00)

	storeView.SetCode(successAddr, successCode)
	storeView.SetCode(revertAddr, revertCode)
	storeView.SetCode(outerAddr, outerCode)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: outerAddr},
		GasLimit: 200000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)
	assert.Equal(1, len(storeView.PopLogs()))
}

// Reverted frame and an earlier successful sub-call share the same
// state root; the parent's checkpoint must still be the one picked.
func TestLogsDroppedWhenRevertedFrameSharesHashWithSubcall(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_l", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	outerAddr := common.HexToAddress("0x0e01000000000000000000000000000000000001")
	middleAddr := common.HexToAddress("0x0e02000000000000000000000000000000000002")
	noopAddr := common.HexToAddress("0x0e03000000000000000000000000000000000003")

	// noop: STOP. Returns success without touching state.
	noopCode := []byte{0x00}

	// middle: LOG0; CALL noop; POP; REVERT. middle reverts, so its LOG
	// should be dropped. noop's snapshot is taken at the same state root
	// because LOG and a no-op CALL don't mutate the trie.
	middleCode := []byte{
		0x60, 0x00, 0x60, 0x00, 0xa0, // LOG0
		0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
		0x73,
	}
	middleCode = append(middleCode, noopAddr.Bytes()...)
	middleCode = append(middleCode, []byte{
		0x61, 0xff, 0xff,
		0xf1,
		0x50,
		0x60, 0x00, 0x60, 0x00,
		0xfd,
	}...)

	// outer: CALL middle; POP; STOP. Outer succeeds.
	outerCode := []byte{
		0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
		0x73,
	}
	outerCode = append(outerCode, middleAddr.Bytes()...)
	outerCode = append(outerCode, []byte{
		0x61, 0xff, 0xff,
		0xf1,
		0x50,
		0x00,
	}...)

	storeView.SetCode(noopAddr, noopCode)
	storeView.SetCode(middleAddr, middleCode)
	storeView.SetCode(outerAddr, outerCode)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: outerAddr},
		GasLimit: 300000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)
	assert.Equal(0, len(storeView.PopLogs()))
}

// Theta moved via the transferTheta precompile inside a reverted frame
// should be unwound with that frame.
func TestThetaTransferRevertedInsideNestedCall(t *testing.T) {
	assert := assert.New(t)

	// Start at a height past HeightSupportThetaTokenInSmartContract so the
	// transferTheta precompile is registered.
	startHeight := common.HeightSupportThetaTokenInSmartContract + 10
	storeView := state.NewStoreView(startHeight, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_c", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)

	innerAddr := common.HexToAddress("0x6000000000000000000000000000000000000006")
	outerAddr := common.HexToAddress("0x7000000000000000000000000000000000000007")
	recipientAddr := common.HexToAddress("0x8000000000000000000000000000000000000008")

	innerStartTheta := big.NewInt(100)
	innerAcc := &types.Account{
		Address: innerAddr,
		Balance: types.Coins{ThetaWei: new(big.Int).Set(innerStartTheta), TFuelWei: big.NewInt(0)},
	}
	storeView.SetAccount(innerAddr, innerAcc)

	// inner: CODECOPY (recipient || amount) to mem[0..52], CALL precompile
	// 0xcb (transferTheta) with that input, POP success, REVERT.
	innerCode := []byte{
		0x60, 0x34, // PUSH1 52    (size to copy)
		0x60, 0x1d, // PUSH1 29    (src in code — data offset, set below)
		0x60, 0x00, // PUSH1 0     (dst in memory)
		0x39, // CODECOPY

		0x60, 0x00, // PUSH1 0     (retSize)
		0x60, 0x34, // PUSH1 52    (retOffset, unused)
		0x60, 0x34, // PUSH1 52    (argsSize)
		0x60, 0x00, // PUSH1 0     (argsOffset)
		0x60, 0x00, // PUSH1 0     (value)
		0x60, 0xcb, // PUSH1 0xcb  (transferTheta precompile)
		0x61, 0xff, 0xff, // PUSH2 0xFFFF (gas)
		0xf1, // CALL
		0x50, // POP

		0x60, 0x00, // PUSH1 0
		0x60, 0x00, // PUSH1 0
		0xfd, // REVERT
	}
	// data starts at offset 0x1d (29): recipient (20 bytes) || amount (32 bytes big-endian)
	innerCode = append(innerCode, recipientAddr.Bytes()...)
	amountBytes := make([]byte, 32)
	amountBytes[31] = 0x64 // 100
	innerCode = append(innerCode, amountBytes...)

	// outer: CALL inner, POP success, STOP.
	outerCode := []byte{
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x60, 0x00,
		0x73,
	}
	outerCode = append(outerCode, innerAddr.Bytes()...)
	outerCode = append(outerCode, 0x61, 0xff, 0xff, 0xf1, 0x50, 0x00)

	storeView.SetCode(innerAddr, innerCode)
	storeView.SetCode(outerAddr, outerCode)

	storeView.IncrementHeight()
	storeView.Save()

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: outerAddr},
		GasLimit: 500000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(startHeight, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	innerFinal := storeView.GetAccount(innerAddr)
	assert.NotNil(innerFinal)
	assert.Equal(0, innerStartTheta.Cmp(innerFinal.Balance.ThetaWei))

	recipientFinal := storeView.GetAccount(recipientAddr)
	if recipientFinal != nil {
		assert.Equal(0, big.NewInt(0).Cmp(recipientFinal.Balance.ThetaWei))
	}
}

// RETURNDATACOPY past the end of the return-data buffer aborts the frame.
// Logs emitted before the abort are dropped with the snapshot.
func TestReturnDataCopyOutOfBoundsAborts(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_d", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	targetAddr := common.HexToAddress("0x9000000000000000000000000000000000000009")

	// LOG0 (empty), then RETURNDATACOPY with size=100 against an empty
	// returnData buffer.
	code := []byte{
		0x60, 0x00, // PUSH1 0   (log data size)
		0x60, 0x00, // PUSH1 0   (log data offset)
		0xa0, // LOG0

		0x60, 0x64, // PUSH1 100 (size — far larger than returnData)
		0x60, 0x00, // PUSH1 0   (src offset in returnData)
		0x60, 0x00, // PUSH1 0   (dst offset in memory)
		0x3e, // RETURNDATACOPY

		0x00, // STOP
	}
	storeView.SetCode(targetAddr, code)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: targetAddr},
		GasLimit: 200000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.NotNil(evmErr)
	assert.Equal(0, len(storeView.PopLogs()))
}

// Revert data from a failed sub-call is readable via RETURNDATA*.
func TestReturnDataFromRevertedCall(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_e", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	innerAddr := common.HexToAddress("0xa000000000000000000000000000000000000010")
	outerAddr := common.HexToAddress("0xb000000000000000000000000000000000000011")

	// inner: CODECOPY 4-byte marker to mem[0..4], REVERT with mem[0..4].
	//   PUSH1 4; PUSH1 <data_off>; PUSH1 0; CODECOPY
	//   PUSH1 4; PUSH1 0; REVERT
	//   <4-byte marker>
	marker := []byte{0xde, 0xad, 0xbe, 0xef}
	innerCode := []byte{
		0x60, 0x04, // PUSH1 4 (size)
		0x60, 0x0c, // PUSH1 12 (src — data offset)
		0x60, 0x00, // PUSH1 0 (dst)
		0x39,       // CODECOPY
		0x60, 0x04, // PUSH1 4 (revert size)
		0x60, 0x00, // PUSH1 0 (revert offset)
		0xfd, // REVERT
	}
	innerCode = append(innerCode, marker...)

	// outer: CALL inner (retSize=0); then RETURNDATACOPY(dst=0, src=0, size=4);
	// LOG0 with mem[0..4]; STOP.
	outerCode := []byte{
		0x60, 0x00, // retSize
		0x60, 0x00, // retOffset
		0x60, 0x00, // argsSize
		0x60, 0x00, // argsOffset
		0x60, 0x00, // value
		0x73,
	}
	outerCode = append(outerCode, innerAddr.Bytes()...)
	outerCode = append(outerCode, []byte{
		0x61, 0xff, 0xff, // PUSH2 gas
		0xf1,       // CALL
		0x50,       // POP success bit
		0x60, 0x04, // PUSH1 4 (size)
		0x60, 0x00, // PUSH1 0 (src in returndata)
		0x60, 0x00, // PUSH1 0 (dst in memory)
		0x3e,       // RETURNDATACOPY
		0x60, 0x04, // PUSH1 4 (log data size)
		0x60, 0x00, // PUSH1 0 (log data offset)
		0xa0, // LOG0
		0x00, // STOP
	}...)

	storeView.SetCode(innerAddr, innerCode)
	storeView.SetCode(outerAddr, outerCode)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: outerAddr},
		GasLimit: 200000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	logs := storeView.PopLogs()
	assert.Equal(1, len(logs))
	if len(logs) == 1 {
		assert.True(bytes.Equal(marker, logs[0].Data))
	}
}

// CREATE2 to an address that already has code returns 0; the existing
// code stays put.
func TestCreate2CollisionPreservesExistingCode(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_f", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)

	creatorAddr := common.HexToAddress("0xc000000000000000000000000000000000000012")
	salt := common.Hash{}
	// initcode: RETURN mem[0..0] — deploys a contract with empty runtime code.
	initcode := []byte{0x60, 0x00, 0x60, 0x00, 0xf3}
	collisionAddr := crypto.CreateAddress2(creatorAddr, salt, crypto.Keccak256(initcode))

	preExistingCode := []byte{0xab, 0xcd, 0xef}
	storeView.SetCode(collisionAddr, preExistingCode)

	// creator: CODECOPY initcode into mem[0..5]; CREATE2(endow=0, off=0,
	// size=5, salt=0); MSTORE result at mem[0]; LOG0 mem[0..32]; STOP.
	// Data section with the 5-byte initcode follows the instruction stream.
	creatorCode := []byte{
		0x60, 0x05, // PUSH1 5  (CODECOPY size)
		0x60, 0x19, // PUSH1 25 (CODECOPY src — data offset, see below)
		0x60, 0x00, // PUSH1 0  (CODECOPY dst)
		0x39, // CODECOPY

		0x60, 0x00, // PUSH1 0  (salt)
		0x60, 0x05, // PUSH1 5  (size)
		0x60, 0x00, // PUSH1 0  (offset)
		0x60, 0x00, // PUSH1 0  (endowment)
		0xf5, // CREATE2

		0x60, 0x00, // PUSH1 0  (MSTORE dst offset)
		0x52,       // MSTORE   (mem[0..32] = create2 result)
		0x60, 0x20, // PUSH1 32 (log data size)
		0x60, 0x00, // PUSH1 0  (log data offset)
		0xa0, // LOG0
		0x00, // STOP
	}
	// Data at offset 25 (0x19): the initcode.
	creatorCode = append(creatorCode, initcode...)

	storeView.SetCode(creatorAddr, creatorCode)

	storeView.IncrementHeight()
	storeView.Save()

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: creatorAddr},
		GasLimit: 500000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	logs := storeView.PopLogs()
	assert.Equal(1, len(logs))
	if len(logs) == 1 {
		assert.True(bytes.Equal(make([]byte, 32), logs[0].Data))
	}

	assert.True(bytes.Equal(preExistingCode, storeView.GetCode(collisionAddr)))
}

// ecrecover on malformed input returns empty output, with CALL reported
// as successful.
func TestEcrecoverMalformedReturnsEmpty(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_g", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	targetAddr := common.HexToAddress("0xd000000000000000000000000000000000000013")

	// CALL ecrecover (precompile 0x01) with empty input; MSTORE success bit at
	// mem[0..32]; MSTORE RETURNDATASIZE at mem[32..64]; LOG0 mem[0..64]; STOP.
	code := []byte{
		0x60, 0x00, // retSize
		0x60, 0x00, // retOffset
		0x60, 0x00, // argsSize
		0x60, 0x00, // argsOffset
		0x60, 0x00, // value
		0x60, 0x01, // addr (ecrecover)
		0x61, 0xff, 0xff, // gas
		0xf1,       // CALL → stack: success
		0x60, 0x00, // dst for MSTORE
		0x52,       // MSTORE mem[0..32] = success
		0x3d,       // RETURNDATASIZE
		0x60, 0x20, // dst
		0x52,       // MSTORE mem[32..64] = returndatasize
		0x60, 0x40, // log size = 64
		0x60, 0x00, // log offset
		0xa0, // LOG0
		0x00, // STOP
	}
	storeView.SetCode(targetAddr, code)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: targetAddr},
		GasLimit: 200000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	logs := storeView.PopLogs()
	assert.Equal(1, len(logs))
	if len(logs) == 1 && len(logs[0].Data) == 64 {
		success := new(big.Int).SetBytes(logs[0].Data[:32])
		returnDataSize := new(big.Int).SetBytes(logs[0].Data[32:])
		assert.Equal(int64(1), success.Int64())
		assert.Equal(int64(0), returnDataSize.Int64())
	}
}

// bn256Add with an off-curve point returns failure; no output.
func TestBn256AddRejectsInvalidPoint(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_h", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	targetAddr := common.HexToAddress("0xe000000000000000000000000000000000000014")

	// code: CODECOPY 128-byte bn256Add input into mem[0..128], CALL 0x06,
	// then log (success, returndatasize).
	code := []byte{
		0x60, 0x80, // PUSH1 128 (CODECOPY size)
		0x60, 0x24, // PUSH1 36  (CODECOPY src — data offset)
		0x60, 0x00, // PUSH1 0   (dst)
		0x39, // CODECOPY

		0x60, 0x00, // retSize
		0x60, 0x00, // retOffset
		0x60, 0x80, // argsSize = 128
		0x60, 0x00, // argsOffset
		0x60, 0x00, // value
		0x60, 0x06, // addr = bn256Add
		0x61, 0xff, 0xff, // gas
		0xf1, // CALL — stack: success

		0x60, 0x00, // MSTORE dst
		0x52,       // MSTORE mem[0..32] = success
		0x3d,       // RETURNDATASIZE
		0x60, 0x20, // MSTORE dst = 32
		0x52, // MSTORE mem[32..64] = returndatasize

		0x60, 0x40, // log size = 64
		0x60, 0x00, // log offset
		0xa0, // LOG0
		0x00, // STOP
	}
	// 128-byte input: point1 = all 0xFF (x exceeds field, off-curve);
	// point2 = (0, 0).
	for i := 0; i < 64; i++ {
		code = append(code, 0xff)
	}
	code = append(code, make([]byte, 64)...)

	storeView.SetCode(targetAddr, code)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: targetAddr},
		GasLimit: 200000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	logs := storeView.PopLogs()
	assert.Equal(1, len(logs))
	if len(logs) == 1 && len(logs[0].Data) == 64 {
		success := new(big.Int).SetBytes(logs[0].Data[:32])
		returnDataSize := new(big.Int).SetBytes(logs[0].Data[32:])
		assert.Equal(int64(0), success.Int64())
		assert.Equal(int64(0), returnDataSize.Int64())
	}
}

// modexp with mod=0 returns modLen zero bytes; no panic on the
// divide-by-zero edge.
func TestModexpZeroModulusReturnsZeros(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_i", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	targetAddr := common.HexToAddress("0xf000000000000000000000000000000000000015")

	// modexp input (130 bytes): baseLen=1, expLen=1, modLen=32, base=2, exp=3,
	// mod = 32 zero bytes. Expected output: 32 zero bytes.
	input := make([]byte, 130)
	input[31] = 0x01 // baseLen=1
	input[63] = 0x01 // expLen=1
	input[95] = 0x20 // modLen=32
	input[96] = 0x02 // base
	input[97] = 0x03 // exp
	// input[98..130] already zero => mod=0

	code := []byte{
		0x60, 0x82, // PUSH1 130 (size)
		0x60, 0x20, // PUSH1 32  (src — data offset)
		0x60, 0x00, // PUSH1 0   (dst)
		0x39, // CODECOPY

		0x60, 0x20, // retSize = 32
		0x60, 0x00, // retOffset
		0x60, 0x82, // argsSize = 130
		0x60, 0x00, // argsOffset
		0x60, 0x00, // value
		0x60, 0x05, // addr = bigModExp
		0x61, 0xff, 0xff, // gas
		0xf1, // CALL → stack: success

		0x60, 0x20, // MSTORE dst = 32
		0x52,       // MSTORE mem[32..64] = success
		0x60, 0x40, // log size = 64
		0x60, 0x00, // log offset
		0xa0, // LOG0 mem[0..64] = (output, success)
		0x00, // STOP
	}
	// data at offset 32
	code = append(code, input...)

	storeView.SetCode(targetAddr, code)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: targetAddr},
		GasLimit: 200000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	logs := storeView.PopLogs()
	assert.Equal(1, len(logs))
	if len(logs) == 1 && len(logs[0].Data) == 64 {
		success := new(big.Int).SetBytes(logs[0].Data[32:])
		assert.Equal(int64(1), success.Int64())
		assert.True(bytes.Equal(make([]byte, 32), logs[0].Data[:32]))
	}
}

// SELFDESTRUCT inside a frame that later reverts is unwound: code,
// balance, and beneficiary unchanged.
func TestSelfdestructRolledBackOnNestedRevert(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_j", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)

	outerAddr := common.HexToAddress("0x0d01000000000000000000000000000000000001")
	middleAddr := common.HexToAddress("0x0d02000000000000000000000000000000000002")
	innerAddr := common.HexToAddress("0x0d03000000000000000000000000000000000003")
	beneficiary := common.HexToAddress("0x0d04000000000000000000000000000000000004")

	// inner: PUSH20 beneficiary; SELFDESTRUCT
	innerCode := []byte{0x73}
	innerCode = append(innerCode, beneficiary.Bytes()...)
	innerCode = append(innerCode, 0xff)

	// middle: CALL inner; POP; REVERT
	middleCode := []byte{
		0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
		0x73,
	}
	middleCode = append(middleCode, innerAddr.Bytes()...)
	middleCode = append(middleCode, []byte{
		0x61, 0xff, 0xff,
		0xf1,
		0x50,
		0x60, 0x00,
		0x60, 0x00,
		0xfd,
	}...)

	// outer: CALL middle; POP; STOP
	outerCode := []byte{
		0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00, 0x60, 0x00,
		0x73,
	}
	outerCode = append(outerCode, middleAddr.Bytes()...)
	outerCode = append(outerCode, []byte{
		0x61, 0xff, 0xff,
		0xf1,
		0x50,
		0x00,
	}...)

	storeView.SetCode(innerAddr, innerCode)
	storeView.SetCode(middleAddr, middleCode)
	storeView.SetCode(outerAddr, outerCode)

	// Seed inner with non-zero TFuel so a stray transfer would be visible.
	innerStartBalance := big.NewInt(100)
	innerAcc := storeView.GetAccount(innerAddr)
	innerAcc.Balance = types.Coins{ThetaWei: big.NewInt(0), TFuelWei: new(big.Int).Set(innerStartBalance)}
	storeView.SetAccount(innerAddr, innerAcc)

	originalCodeHash := storeView.GetAccount(innerAddr).CodeHash

	storeView.IncrementHeight()
	storeView.Save()

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: outerAddr},
		GasLimit: 300000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	innerFinal := storeView.GetAccount(innerAddr)
	assert.NotNil(innerFinal)
	assert.Equal(originalCodeHash, innerFinal.CodeHash)
	assert.False(storeView.HasSuicided(innerAddr))
	assert.Equal(0, innerStartBalance.Cmp(innerFinal.Balance.TFuelWei))

	benFinal := storeView.GetAccount(beneficiary)
	if benFinal != nil {
		assert.Equal(0, big.NewInt(0).Cmp(benFinal.Balance.TFuelWei))
	}
}

// CREATE rejects initcode whose returned runtime bytecode exceeds
// MaxCodeSize (EIP-170).
func TestCreateRejectsOversizedCode(t *testing.T) {
	assert := assert.New(t)

	storeView := state.NewStoreView(0, common.Hash{}, backend.NewMemDatabase())

	caller := types.MakeAccWithInitBalance("caller_k", types.NewCoins(0, 50000000000))
	storeView.SetAccount(caller.Address, &caller.Account)
	storeView.IncrementHeight()
	storeView.Save()

	creatorAddr := common.HexToAddress("0x1100000000000000000000000000000000000016")

	// creator: CODECOPY 6-byte initcode into mem[0..6]; CREATE with it;
	// MSTORE CREATE's return onto mem[0..32]; LOG0 mem[0..32]; STOP.
	// The initcode returns mem[0..24577] — one byte past MaxCodeSize.
	creatorCode := []byte{
		0x60, 0x06, // PUSH1 6  (CODECOPY size)
		0x60, 0x17, // PUSH1 23 (CODECOPY src — data offset)
		0x60, 0x00, // PUSH1 0  (dst)
		0x39, // CODECOPY

		0x60, 0x06, // PUSH1 6 (CREATE size)
		0x60, 0x00, // PUSH1 0 (offset)
		0x60, 0x00, // PUSH1 0 (value)
		0xf0, // CREATE

		0x60, 0x00, // PUSH1 0 (MSTORE dst)
		0x52,       // MSTORE
		0x60, 0x20, // PUSH1 32 (log size)
		0x60, 0x00, // PUSH1 0  (log offset)
		0xa0, // LOG0
		0x00, // STOP
	}
	// initcode (6 bytes): RETURN mem[0..24577].
	initcode := []byte{0x61, 0x60, 0x01, 0x60, 0x00, 0xf3}
	creatorCode = append(creatorCode, initcode...)

	storeView.SetCode(creatorAddr, creatorCode)

	tx := &types.SmartContractTx{
		From:     types.TxInput{Address: caller.Address},
		To:       types.TxOutput{Address: creatorAddr},
		GasLimit: 10000000,
		GasPrice: big.NewInt(50),
		Data:     nil,
	}

	blockInfo := vm.NewBlockInfo(1, big.NewInt(1), "test_chain")
	_, _, _, evmErr := vm.Execute(blockInfo, tx, storeView)

	assert.Nil(evmErr)

	logs := storeView.PopLogs()
	assert.Equal(1, len(logs))
	if len(logs) == 1 && len(logs[0].Data) == 32 {
		assert.True(bytes.Equal(make([]byte, 32), logs[0].Data))
	}
}
