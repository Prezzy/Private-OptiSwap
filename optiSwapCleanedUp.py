#from protocol.Extract import optiParsePhi
from protocol.CircuitTransformer import transform
from protocol.MrkTree import MerkleTree, mVrfy
from protocol.encryption import dec, enc
import copy
import json
from web3 import Web3, HTTPProvider
from os import urandom
from merkletools import MerkleTools
blockchain_address = 'http://127.0.0.1:9545'

CIRCUIT_SIZE = 50


web3 = Web3(HTTPProvider(blockchain_address))

web3.eth.defaultAccount = web3.eth.accounts[0]

compiled_contract_path = 'build/contracts/pOptiJudge.json'

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



def NextChallengeLow(focusGates, responses):
    challenge = set()
    inputs = set()
    for i in focusGates:
        for j in expPhiStructAbv[int(i)]:
            challenge.add(j)
    for i in challenge:
        if buyerHashes[i] != responses[i][1]:
            print("New Focus gate {}".format(i))
            focusGates = [i]
            challenge = set()
            for j in expPhiStructAbv[i]:
                challenge.add(j)
            return(focusGates, challenge)

    print("we need to complain AGAIN!")
    return (focusGates, False)


#INPUT focusGates: array high lvl index of current who inputs are to be queried
#INPUT responses: responses recieved so far just needs to keep track of indexes
def NextChallenge(focusGates, responses):
    challenge = set()
    inputs = set()
    reverseMap = {}
    if responses:
        for i in focusGates:
            for j in phiStructAbv[int(i)]:
                for k in mapping[j]:
                    reverseMap[k] = j
                    inputs.add(k)

        for k in inputs:
            if k in responses.keys():
                challenge.add(k)
        for l in inputs:
            if l not in challenge:
                print("not expected??")
                print("challenge {} and inputs {}".format(challenge, inputs))
                return (focusGates, challenge.difference(inputs))
        for i in challenge:
            if buyerHashes[i] != responses[i][1]: #challenge i highlvl and k lowlvl
                    #Need to check if it is part of witness, if so then complain. 
                print("new focus Gate {}".format(reverseMap[i]))
                focusGates = [reverseMap[i]]
                challenge = set()
                for j in phiStructAbv[reverseMap[i]]:
                    for k in mapping[j]:
                        challenge.add(k)
                return (focusGates, challenge)

        print("we need to complain")
        print("Cur focusGate {}".format(focusGates))
        return (focusGates, False)
    else:
        for i in focusGates:
            for j in phiStructAbv[int(i)]:
                for k in mapping[int(j)]:
                    challenge.add(k)
        return (focusGates, challenge)


def generateResponse(queries, state):

    response = {}
    if(state == 0):
        for i in queries:
            mrkProof = encodeProof(sellerMerkTree.get_proof(int(i)))
            response[i] = (i,sellerHashes[int(i)],mrkProof)
    elif(state == 1):
        for i in queries:
            mrkProof = encodeProof(sellerMerkTree.get_proof(int(i)))
            response[i] = (i,sellerHashes[int(i)],mrkProof)

    return response


def validateResponses(query, response, hashRoot, state):
    if(state == 0):
        matching = set()
        responseIdx = set()
        for idx in response:
            responseIdx.add(idx)
        for q in query:
            if q not in responseIdx:
                print("Sender sent incorrect responses {}")
                return (False,q1)
            elif not mVrfy(q, response[q][1], response[q][2], sellerHashRoot):
                print("Merkle Proofs not valid")
                return (False,-1)
        for idx in response:
            if(buyerHashes[idx] == response[idx][1]):
                matching.add(idx)
        return (True,matching)
    elif(state == 1):
        matching = set()
        responseIdx = set(response.keys())
        for i in query:
            if i not in responseIdx:
                print("Sender send incorrect response {}")
                return (False, i)
            elif not mVrfy(i, response[i][1], response[i][2], sellerHashRoot):
                print("Merkle Proofs not valid")
                return (False, -1)
        for i in query:
            if(buyerHashes[i] == response[i][1]):
                matching.add(i)
        return (True, matching)

def generatePOM(focusGates, responses):
    gasPOM = []

    inputs = expPhiStructAbv[focusGates[0]]

    gateIdx = focusGates[0]
    gateValue = expPhiStructure[gateIdx]
    gateProof = encodeProof(expPhiMerkleTree.get_proof(gateIdx))

    print("Len of gateProof {}".format(len(gateProof)))

    gateParts = gateValue.split(",")
    gateParts = gateParts[0].split("-")
    constMulVal = int(gateParts[2],16)

    inIdx = int(inputs[0])
    #inElement = z[inIdx]
    #inProof = encodeProof(zMerkTree.get_proof(inIdx))
    inElement = responses[inIdx][1]
    inProof = responses[inIdx][2]
    print("Len of inProof {}".format(len(inProof)))
    #inProof = encodeProof(zMerkTree.get_proof(inIdx))

    inPlain = dec(inIdx, keyEnc, z[inIdx])

    outIdx = focusGates[0]
    outElement = responses[outIdx][1]
    outProof = responses[outIdx][2]

    print("From merk tree {}".format(sellerMerkTree.get_leaf(outIdx)))
    print("From POM {}".format(outElement.hex()))

    msgHash = contract.functions.judge(gateProof, gateValue, outProof, outElement, outIdx, inProof, inElement, inIdx, inPlain, constMulVal).transact()

    print("POM trans hash {}".format(msgHash.hex()))

    tx_receipt = web3.eth.waitForTransactionReceipt(msgHash)

    gasPOM.append(tx_receipt.gasUsed)

    return gasPOM


def disputeResolution():

    focusGates = [path[0]]
    responses = {}
    lowResponses = {}
    count = 0
    state = 0
    gasResponse = []
    gasQuery = []
    numResponses = 0
    numQueries = 0
    while(True):

        if(state == 0):
            (focusGates, queries) = NextChallenge(focusGates, responses)

            if(queries == False):
                print("Complain")
                state = 1
                
                print("switching new state")
                temp = mapping[focusGates[0]]
                queries = set()
                focusGates = []
                for i in temp:
                    focusGates.append(i)
                    temp1 = expPhiStructAbv[i]
                    for j in temp1:
                        queries.add(j)

                qListToSend = list(queries)

                #SENDING QUERIES
                #messageHash = contract.functions.storeQueries(qListToSend).transact()
            else:
                qListToSend = []
                for i in queries:
                    qListToSend.append(i)

            messageHash = contract.functions.storeQueries(qListToSend).transact()
            numQueries += 1

            tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)

            print("Gas used to store one query {}".format(tx_receipt.gasUsed))

            gasQuery.append(tx_receipt.gasUsed)


            response = generateResponse(qListToSend, state)

            rToSend = []
            for idx in response:
                hash1 = response[idx][1]
                proof = response[idx][2]
                rToSend.append([idx,hash1,proof])

            gasUsed = 0
            for rep in rToSend:
                messageHash2 = contract.functions.storeResponse(rep[0],rep[1],rep[2]).transact()

                tx_receipt = web3.eth.waitForTransactionReceipt(messageHash2)
                gasUsed += tx_receipt.gasUsed
                gasResponse.append(tx_receipt.gasUsed)
            print("gasUsed to store a single response {}".format(gasUsed))
            numResponses += 1



            #(valid, matches) = validateResponses(qListToSend, response, sellerHashRoot, state)


            #if(valid):
            for key in response:
                responses[key] = response[key]


        else:
            (focusGates, queries) = NextChallengeLow(focusGates, responses)

            if(queries == False):
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
                print("Total # Queries {}".format(numQueries))
                print("Total # Responses {}".format(numResponses))
                
                return


            qListToSend = list(queries)
            print("queries {}".format(qListToSend))
            
            messageHash = contract.functions.storeQueries(qListToSend).transact()
            tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)

            numQueries += 1

            print("gas used to store single query inside Gadget {}".format(tx_receipt.gasUsed))

            gasQuery.append(tx_receipt.gasUsed)
       
            lowResponses = generateResponse(qListToSend, state)

            rToSend = []
            for idx in lowResponses:
                h = lowResponses[idx][1]
                proof = lowResponses[idx][2]
                rToSend.append([idx, h, proof])

            gasUsed = 0
            for rep in rToSend:
                messageHash = contract.functions.storeResponse(rep[0],rep[1],proof).transact()

                tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
                gasUsed += tx_receipt.gasUsed
                gasResponse.append(tx_receipt.gasUsed)

            print("Gas used to store response inside gadget {}".format(gasUsed))
            numResponses += 1


            #(valid, matches) = validateResponses(qListToSend, lowResponses, sellerHashRoot, state)

            #if (valid):
            for key in lowResponses:
                responses[key] = lowResponses[key]



def sellerHash(sellerExpLines):
    sellerHashes = [0] * len(sellerExpLines)
    for line in sellerExpLines:
        (idx, value) = line.split(" ")
        value = value.rstrip()
        if value == '-0x1':
            value = '0xffffffff'
        value = '0x' + '0' * (64 - (len(value)-2)) + value[2:]
        sellerHashes[int(idx)] = bytes(Web3.keccak(hexstr=value))
    return sellerHashes

#get circuit file to transform text file into usable data structures
phiFile = open("circuit/circuit-{}".format(CIRCUIT_SIZE), "r")
phiLines = phiFile.readlines()

phiLinestrans = copy.deepcopy(phiLines)


(mapping, outFileWrite) = transform(phiLinestrans, (2**32), (32)//8)

phiFile.close()

phiFileExp = open("circuit/circuit-ex-{}".format(CIRCUIT_SIZE), "r")
phiLinesExp = phiFileExp.readlines()
phiFileExp.close()

(phiStructure, outputs, distance, phiStructAbv) = optiParsePhi(phiLines)
(expPhiStructure, expOutputs, expDistance, expPhiStructAbv) = optiParsePhi(phiLinesExp)



(depth, path) = getdepth(phiStructure, outputs, distance)
secondLast = path[-2]
(depthExp, pathExp) = getdepth(expPhiStructure, mapping[secondLast], expDistance)

path = path[0:-2]
queryPath = []
for i in path:
    queryPath.append(mapping[i][0])

queryPath = queryPath+pathExp[0:-1]

sellerExpFile = open("circuit/wires-ex-{}".format(CIRCUIT_SIZE), "r")
sellerExpLines = sellerExpFile.readlines()

#Create array of hash CORRECT hashes for sender

sellerHashes = sellerHash(sellerExpLines)

print("Before Buyer Merkle Tree")
#make copy of CORRECT hashes for buyer and get merkle tree of this
buyerHashes = copy.deepcopy(sellerHashes)
buyerMerkTree = MerkleTools()
buyerMerkTree.add_leaf(buyerHashes)
buyerMerkTree.make_tree()
buyerHashRoot = buyerMerkTree.get_merkle_root()
print("End Buyer Merk Tree")

#Corrupt the path down to first gate whose inputs are chunks of the witness
print("Corrupting Seller Path")
for i in queryPath:
    value = '0x' + 'af' * 32
    sellerHashes[i] = bytes(Web3.keccak(hexstr=value))
print("End corrupting path")


print("Before Seller Merkle Tree")
sellerMerkTree = MerkleTools() 
sellerMerkTree.add_leaf(sellerHashes)
sellerMerkTree.make_tree()
sellerHashRoot = sellerMerkTree.get_merkle_root()
print("End Seller Merk Tree")

sellerHashRoot = bytes.fromhex(sellerHashRoot)

messageHash = contract.functions.storehRoot(sellerHashRoot).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("Seller hashes Stored")
with open("circuit/en-inputs-{}".format(CIRCUIT_SIZE), "r") as file:
    inputs = file.readlines()


print("len inputs {}".format(len(inputs)))
z = [0] * len(inputs)

print("Generating Key and Encrypting Input")
keyEnc = urandom(32)
for index in range(len(inputs)):
    plainText = inputs[index]
    plainText = plainText.split(" ")[1].strip()
    plainText = int(plainText,16)
    z[index]= (enc(index, keyEnc, plainText))

messageHash = contract.functions.storeKey(keyEnc).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("Key Stored")

print("Creating encrypted input (z) merk tree")
zMerkTree = MerkleTools()
zMerkTree.add_leaf(z, True)
zMerkTree.make_tree()
zRoot = zMerkTree.get_merkle_root()
print("Done making merk tree for z")
messageHash = contract.functions.storezRoot(zRoot).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("stored z root")


print("Making Merkle tree for expanded circuit")
expPhiMerkleTree = MerkleTools()
expPhiMerkleTree.add_leaf(expPhiStructure,True,True)
expPhiMerkleTree.make_tree()
phiRoot = expPhiMerkleTree.get_merkle_root()
print("done making merk tree for expanded circuit")


messageHash = contract.functions.storePhiRoot(phiRoot).transact()
tx_receipt = web3.eth.waitForTransactionReceipt(messageHash)
print("stored Phi root")


print("Beginning Dispute Resolution")
disputeResolution()

