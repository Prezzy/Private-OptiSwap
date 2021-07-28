#from protocol.Extract import optiParsePhi
from protocol.encryption import enc
from protocol.CircuitTransformer import transform
from protocol.MrkTree import MerkleTree, mVrfy
from merkletools import MerkleTools
import copy
import json
from web3 import Web3, HTTPProvider
from os import urandom
from eth_abi.packed import encode_abi_packed

CIRCUIT_SIZE = 50

blockchain_address = 'http://127.0.0.1:9545'

web3 = Web3(HTTPProvider(blockchain_address))

web3.eth.defaultAccount = web3.eth.accounts[0]

compiled_contract_path = 'build/contracts/OptiJudge.json'

deployed_contract_address = '0x945315bbCc2058Ed5232C5a0C54dd47481446713'

with open(compiled_contract_path) as file:
    contract_json = json.load(file)
    contract_abi = contract_json['abi']

contract = web3.eth.contract(address=deployed_contract_address, abi=contract_abi)

def encodeProof(proof):
    newProof = []
    for i in proof:
        try:
            newProof.append([bytes([0]), bytes.fromhex(i['left'])])
        except:
            newProof.append([bytes([1]), bytes.fromhex(i['right'])])
    return newProof


def optiParsePhi(phi):

    outputs = []
    distance = []
    phiStructure = []
    phiStructAbv = []
    for gate in phi:
        gateParts = gate.split(" ")
        if(gateParts[0] == "total"):
            numWires = int(gateParts[1])
            phiStructure = [0] * numWires
            distance = [0] * numWires
            phiStructAbv = [[-1]] * numWires
        elif (gateParts[0] == "input"):
            wireId = int(gateParts[1])
            phiStructure[wireId] = gateParts[0]
            distance[wireId] = 0
        elif(gateParts[0] == "output"):
            outputs.append("{}".format(gateParts[1].rstrip('\n'))) 
        else:
            numIn = gateParts[2]
            op = gateParts[0]
            if(int(numIn) == 2):
                in1 = gateParts[3]
                in1Idx = int(in1.strip('<'))
                in2 = gateParts[4]
                in2Idx = int(in2.strip('>'))
                data = "{}, {} {}".format(op, in1, in2)
                wireId = gateParts[7].rstrip('\n').rstrip('>').lstrip('<')
                distance[int(wireId)] = max(distance[in1Idx]+1, distance[in2Idx]+1)
                phiStructAbv[int(wireId)] = [in1Idx, in2Idx]
            else:
                data = "{}, {}".format(op, gateParts[3])
                idx = int(gateParts[3].strip('<').strip('>'))
                wireId = gateParts[6].rstrip('\n').rstrip('>').lstrip('<')
                distance[int(wireId)] = distance[idx] + 1
                phiStructAbv[int(wireId)] = [idx]
            phiStructure[int(wireId)] = data
    return (phiStructure, outputs, distance, phiStructAbv)


def getdepth(phiStructure, outputs, distance):

    path = []

    tallestPoint = 0
    for idx in outputs:
        idx = int(idx)
        if(tallestPoint == 0):
            tallestPoint = idx
        else:
            if distance[tallestPoint] < distance[idx]:
                tallestPoint = idx

    path.append(tallestPoint)

    nextLvl = phiStructure[tallestPoint]


    splitNextLvl = nextLvl.split(", ")
    splitNextLvl[1] = splitNextLvl[1].replace('<', "")
    splitNextLvl[1] = splitNextLvl[1].replace('>',"")
    inputs = splitNextLvl[1].split(" ")

    if len(inputs) == 1:
        focusGate = int(inputs[0])
    elif len(inputs) == 2:
        left = int(inputs[0])
        right = int(inputs[1])
        if(distance[left] <= distance[right]):
            focusGate = right
        else:
            focusGate = left
    else:
        print("mistakes were made: num inputs incorrect")

    path.append(focusGate)

    depth = 1
    while True:
        nextLvl = phiStructure[focusGate]
        if (nextLvl == 'input'):
            print("reached input")
            break;

        splitNextLvl = nextLvl.split(", ")
        splitNextLvl[1] = splitNextLvl[1].replace('<', "")
        splitNextLvl[1] = splitNextLvl[1].replace('>',"")
        #print(splitNextLvl[1])
        inputs = splitNextLvl[1].split(" ")
        #print(inputs)

        if len(inputs) == 1:
            focusGate = int(inputs[0])
        elif len(inputs) == 2:
            left = int(inputs[0])
            right = int(inputs[1])

            #print(mapping[left])
            #print(mapping[right])

            if(distance[left] <= distance[right]):
                focusGate = right
            else:
                focusGate = left
        else:
            print("mistakes were made: num inputs incorrect")
        #print(focusGate)
        depth += 1
        path.append(focusGate)
        #print(focusGate)
        #print(mapping[focusGate])
        #print("hello")

    return (depth, path)

    


def prettyProof(proof):
    proofString = "["
    for i in proof[:-1]:
        proofString += "\"{}\",".format(i.hex())

    proofString += "\"{}\"]".format(proof[-1].hex())

    return proofString


def NextChallenge(focusGates, responses):
    challenge = set()
    inputs = set()
    if responses:
        for i in focusGates:
            for j in phiStructAbv[int(i)]:
                inputs.add(j)

        for k in inputs:
            if k in responses.keys():
                challenge.add(k)
        for l in inputs:
            if l not in challenge:
                print("not expected??")
                print("challenge {} and inputs {}".format(challenge, inputs))
                return (focusGates, challenge.difference(inputs))
        for i in challenge:
            if buyerEncryptedWires[i] != responses[i][1]:
                    #Need to check if it is part of witness, if so then complain. 
                print("new focus Gate {}".format(i))
                focusGates = [i]
                challenge = set()
                for j in phiStructAbv[i]:
                    challenge.add(j)
                return (focusGates, challenge)

        print("we need to complain")
        print("Cur focusGate {}".format(focusGates))
        return (focusGates, False)
    else:
        for i in focusGates:
            for j in phiStructAbv[int(i)]:
                challenge.add(j)
        return (focusGates, challenge)


def generateResponse(queries):

    response = {}
    for i in queries:
        mrkProof = sellerMerkTree.get_proof(int(i))
        response[i] = (i,sellerEncryptedWires[int(i)],mrkProof)
    return response


def validateResponses(query, response, hashRoot):
    matching = set()
    responseIdx = set()
    for idx in response:
        responseIdx.add(idx)
    for q in query:
        if q not in responseIdx:
            return (False,q1)
        elif not sellerMerkTree.validate_proof(response[q][2], Web3.keccak(response[q][1]).hex()[2:], sellerEncRoot):
            print("Merkle Proofs not valid")
            return (False,-1)
    for idx in response:
        if(buyerEncryptedWires[idx] == response[idx][1]):
            matching.add(idx)
    return (True,matching)

def generatePOM(focusGates, responses):

    gasPOM = []

    inputs = phiStructAbv[focusGates[0]]

    gateIdx = focusGates[0]
    gateValue = phiStructure[focusGates[0]]
    gateProof = encodeProof(cirMerkTree.get_proof(gateIdx))

    print("Len gateProof {}".format(len(gateProof)))

    gateParts = gateValue.split(",")
    gateParts = gateParts[0].split("-")
    constMulVal = int(gateParts[2],16)

    inIdx = int(inputs[0])
    print("input Idx {}".format(inIdx))
    inElement = responses[inIdx][1]
    inProof = encoreProof(responses[inIdx][2])

    print("Len inProof {}".format(len(inProof)))

    outIdx = focusGates[0]
    outElement = responses[outIdx][1]
    outProof = encodeProof(responses[outIdx][2])

    msgHash = contract.functions.judge(gateProof, gateValue, outProof, outElement, outIdx, inProof, inElement, inIdx, constMulVal).transact()

    print(msgHash.hex())

    tx_receipt = web3.eth.waitForTransactionReceipt(msgHash)

    gasPOM.append(tx_receipt.gasUsed)

    return gasPOM


def disputeResolution():

    focusGates = [path[0]]
    responses = {}
    count = 0
    gasResponse = []
    gasQuery = []
    numberResponses = 0
    numberQueries = 0

    while(True):
        (focusGates, queries) = NextChallenge(focusGates, responses)

        if(not queries):
            print("we need to complain")
            gasPOM = generatePOM(focusGates, responses)
            responseTotal = 0
            for i in gasResponse:
                responseTotal += int(i)

            queryTotal = 0
            for i in gasQuery:
                queryTotal += int(i)

            pomTotal = 0
            for i in gasPOM:
                pomTotal += int(i)

            print("Total Gas Response {}".format(responseTotal))
            print("Total Gas Query {}".format(queryTotal))
            print("Total Gas POM {}".format(pomTotal))
            print("Total # Quesiers {}".format(numberQueries))
            print("Total # Responses {}".format(numberResponses))
            return

        qListToSend = []
        for i in queries:
            qListToSend.append(i)

        numberQueries += 1
        messageHash = contract.functions.storeQueries(qListToSend).transact()

        tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)

        gasQuery.append(tx_receipt.gasUsed)

        response = generateResponse(qListToSend)


        rToSend = []
        for idx in response:
            cipher = response[idx][1]
            proof = encodeProof(response[idx][2])
            rToSend.append([idx,cipher,proof])

        for rep in rToSend:
            messageHash2 = contract.functions.storeResponse(rep[0],rep[1],rep[2]).transact()
            
            tx_receipt = web3.eth.waitForTransactionReceipt(messageHash2)

            gasResponse.append(tx_receipt.gasUsed)

        print(response)

        numberResponses += 1
        (valid, matches) = validateResponses(qListToSend, response, sellerEncRoot)


        if(valid):
            for key in response:
                responses[key] = response[key]






#get circuit file to transform text file into usable data structures

phiFile = open("circuit/circuit-{}".format(CIRCUIT_SIZE), "r")
phiLinesSeller = phiFile.readlines()

phiLinesBuyer = copy.deepcopy(phiLinesSeller)
phiFile.close()


(phiStructure, outputs, distance, phiStructAbv) = optiParsePhi(phiLinesSeller)
(depth, path) = getdepth(phiStructure, outputs, distance)


path = path[0:-1]

sellerWireFile = open("circuit/wires-{}".format(CIRCUIT_SIZE), "r")
sellerWires = sellerWireFile.readlines()
sellerEncryptedWires = [0] * len(sellerWires)
sellerWireFile.close()

buyerWireFile = open("circuit/wires-{}".format(CIRCUIT_SIZE), "r")
buyerWires = buyerWireFile.readlines()
buyerEncryptedWires = [0] * len(buyerWires)
buyerWireFile.close()

with open("circuit/inputs-{}".format(CIRCUIT_SIZE), "r") as file:
    inputs = file.readlines()


z = [0] * len(inputs)

keyEnc = urandom(32)

for index in range(len(inputs)):
    plainText = inputs[index]
    plainText = plainText.split(" ")[1].strip()
    plainText = int(plainText, 16)
    z[index] = (enc(index, keyEnc, plainText))

print("len of z {}".format(len(z)))

print("Encrypting and corrupting seller's")
for line in sellerWires:
    (idx, value) = line.split(" ")
    value = value.rstrip()
    if value == '-0x1':
        value = '0xffffffff'
    
    buyerEncryptedWires[int(idx)] = enc(int(idx),keyEnc,int(value,16))
    if int(idx) in path:
        value = '0xafafafaf'
    sellerEncryptedWires[int(idx)] = enc(int(idx),keyEnc,int(value,16))
print("Done Encryption")

messageHash = contract.functions.storeKey(keyEnc).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("Key Stored")

#print("Before Buyer Merkle Tree")
#buyerMerkTree = MerkleTools()
#buyerMerkTree.add_leaf(buyerHashes)
#buyerMerkTree.make_tree()
#buyerHashRoot = buyerMerkTree.get_merkle_root()
#print("End Buyer Merk Tree")

print("Before Seller z Merk Tree")
zMerkTree = MerkleTools()
zMerkTree.add_leaf(z, True)
zMerkTree.make_tree()
zRoot = zMerkTree.get_merkle_root()
print("Done Z Merk Tree")

messageHash = contract.functions.storezRoot(zRoot).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("Stored Z root")

print("Before Seller Merkle Tree")
sellerMerkTree = MerkleTools()
sellerMerkTree.add_leaf(sellerEncryptedWires, True)
sellerMerkTree.make_tree()
sellerEncRoot = sellerMerkTree.get_merkle_root()
#???Why do I need merkDepth???
#merkDepth = sellerMerkTree.getDepth()
print("Done merkle seller tree")

messageHash = contract.functions.storeeRoot(sellerEncRoot).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("Seller stored encrypted cir Merk tree")

print("Making Merkle tree for circuit")
cirMerkTree = MerkleTools()
cirMerkTree.add_leaf(phiStructure, True, True)
cirMerkTree.make_tree()
phiRoot = cirMerkTree.get_merkle_root()
print("Done making merk tree for circuit")

messageHash = contract.functions.storePhiRoot(phiRoot).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("stored Phi root")


print("Beginning Dispute Resolution")
disputeResolution()
