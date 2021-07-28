pragma solidity >=0.7.0 < 0.8.0;
//pragma experimental ABIEncoderV2;

/**
 * @title Judge
 * @dev To experiment with Gas cost of various Proof of misbehaviour
 */
contract pOptiJudge {

    uint public refund;

    bytes32 zRoot;

    bytes32 hRoot;

    bytes32 phiRoot;

    bytes32 key;
 
    struct Gadgetresponse {
	uint idx;
	bytes32 hash;
	bytes32[2][] proof;
    }


    mapping (uint => Gadgetresponse) responses;
        
    uint32[] previousQ;
        
    uint32[] currentQ;


    function storezRoot(bytes32 zroot) public {
	zRoot = zroot;
    }


    function storehRoot(bytes32 hroot) public {
	hRoot = hroot;
    }


    function storePhiRoot(bytes32 proot) public {
	phiRoot = proot;
    }

    function storeKey(bytes32 keyEnc) public {
	key = keyEnc;
    }	


    function storeResponse(uint idx, bytes32 hash, bytes32[2][] memory proof) public returns (bool){
	Gadgetresponse memory myGate = Gadgetresponse(idx, hash, proof);
	responses[idx] = myGate;
	return true;
    }


	function validateResponse() internal returns (bool) {
		
		for(uint i = 0; i < currentQ.length; i++){
			if(responses[currentQ[i]].idx == 0) {
				return false;
			} else {
				if(mVrfy(responses[currentQ[i]].proof, responses[currentQ[i]].hash, hRoot) == false){
					return false;
				}
			}
		}

		return true;
	}



    function storeQueries(uint32[] calldata queries) public returns (bool) {

	//delete from responses mapping when updating previous queries
	for(uint i = 0; i < previousQ.length; i++){
		delete responses[previousQ[i]];
	}        

	
        previousQ = currentQ;
        
        currentQ = queries;
        
        return true;
        
    }


  
    function dec(uint256 idx, bytes32 decKey, bytes32 ciphertext) public pure returns (bytes32) {
    
        bytes32 key_i_hash = keccak256(abi.encodePacked(decKey, idx));
        
        return ciphertext ^ key_i_hash;
        
    }
    
    function modComp(uint256 val1, uint256 val2) public view returns (uint256){
        
        uint256 product = val1 * val2;
        
        uint256 result = product % 2**32;
        
        return result;
    }
  
/*  
    function mVrfyGate(uint256 idx, string memory element, bytes32[] memory proof, bytes32 root) public pure returns (bool){
        
        bytes32 hash1 = keccak256(abi.encodePacked(element));
        
        for(uint i = 0; i < proof.length; i++){
            if((idx / uint256(2**i) % 2) == 0){
                hash1 = keccak256(abi.encodePacked(hash1, proof[i]));
            } else {
                hash1 = keccak256(abi.encodePacked(proof[i], hash1));
            }
        }
        
        if(hash1 == root){
            return true;
        } else {
            return false;
        }
    }

*/

    function mVrfy(bytes32[2][] memory proof, bytes32 target_hash, bytes32 merkle_root) public pure returns (bool) {
	bytes32 proof_hash;
	bytes32 sibling;
	if(proof.length == 0){
	    return target_hash == merkle_root;
	} else {
	    proof_hash = target_hash;
	    for(uint i = 0; i < proof.length; i++){
		if(proof[i][0] == 0x00){
		    sibling = proof[i][1];
		    proof_hash = keccak256(abi.encodePacked(sibling,proof_hash));
		} else {
		    sibling = proof[i][1];
		    proof_hash = keccak256(abi.encodePacked(proof_hash, sibling));
		}
	    }
	}

	if(proof_hash == merkle_root){
	    return true;
	} else {
	    return false;
	}

    }

/*
      function mVrfy(uint256 idx, bytes32 element, bytes32[] memory proof, bytes32 root) public pure returns (bool){
        
        bytes32 hash1 = keccak256(abi.encodePacked(element));
        
        for(uint i = 0; i < proof.length; i++){
            if(((idx / uint256(2**i)) % 2) == 0){
                hash1 = keccak256(abi.encodePacked(hash1, proof[i]));
            } else {
                hash1 = keccak256(abi.encodePacked(proof[i], hash1));
            }
        }
        
        if(hash1 == root){
            return true;
        } else {
            return false;
        }
    }
    
    function storeGateProof(uint256 idx, string memory element, bytes32[2][] memory proof) public {
        gateIdx = idx;
        gateDes = element;
        gateProof = proof;

	bool valid = false;
	for(uint i = 0; i < previousQ.length; i++){
		if(previousQ[i] == idx){
			valid = true;
		}
    	}
  }
    
    function storeOutProof(uint256 idx, bytes32 element, bytes32[2][] memory proof) public {
        outIdx = idx;
        outHash = element;
        outProof = proof;
	bool valid = false;
	for(uint i = 0; i < previousQ.length; i++){
		if(currentQ[i] == idx){
			valid = true;
		}
	}

    }
    
    function storeIn1Proof(uint256 idx, bytes32 element, bytes32[2][] memory proof) public {
        in1Idx = idx;
        in1Enc = element;
        in1Proof = proof;
	bool valid = false;
	for(uint i = 0; i < currentQ.length; i++){
		if(currentQ[i] == idx){
			valid = true;
		}
	}
    }

	function storeConstMulVal(uint256 val) public {
		constMulVal = val;
	}


*/
  
    function judge(bytes32[2][] memory gateProof, string memory gateDes, bytes32[2][] memory outProof, bytes32 outHash, uint256 outIdx, bytes32[2][] memory inProof, bytes32 inEnc, uint256 inIdx, bytes32 inPlain, uint256 constMulVal) external returns (bool){


	//if(validateResponse() == false){
	//	return false;
	//}

	 if(responses[outIdx].hash != outHash){
                return false;
        }
        
	bytes32 gate_target_hash = keccak256(abi.encodePacked(gateDes));

        if(mVrfy(gateProof, gate_target_hash, phiRoot) == false){
            
            return false;
        }


	if(mVrfy(outProof, outHash, hRoot) == false){

		return false;
	}

	//bytes32 in1_target_hash = keccak256(abi.encodePacked(inEnc));        

        if(mVrfy(inProof, inEnc, hRoot) == false){
            
            return false;
        }

	bytes32 testHash = keccak256(abi.encodePacked(inPlain));
        
	if(inEnc != testHash){
		return false;
	}
        
        //bytes32 inPlain = dec(inIdx, key, inEnc);
        
        uint256 result = modComp(uint256(inPlain), constMulVal);

	bytes32 resultHash = keccak256(abi.encodePacked(result));
    
        if(resultHash != outHash){
            return true;
        } else {
            return false;   
        }
 
    }

    
}
