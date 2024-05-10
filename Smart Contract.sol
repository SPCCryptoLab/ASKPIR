
pragma solidity >=0.4.24;
import "./VerifyRingSignaturePrecompiled.sol";
pragma experimental ABIEncoderV2;

contract SmartContract{
    mapping (uint =>string) uidList;//授权计算证明uid列表
    uint numUID=0;//uid个数
    mapping(uint =>string) proofList;//授权证明proof
    uint numProofs=0;//proof数量
    //一个did document
    struct DID{
        string id;
        string controller;
        string []verificationMethod;
        string []assertionMethod;
    }
    DID [] didList;//did document列表
    uint numofdid = 0;
    function getVerifyResult() public view returns(string memory){
        return result;
    }
    function selectTag(string memory tag) private view returns(bool){
        //初始化返回值
        bool resul = true;
         for(uint i =0;i<numTag;i++){
            if(keccak256(abi.encode(tagList[i]))==keccak256(abi.encode(tag))){
                resul = false;
                break;
            }
        }
        return resul;
    }
    //this one 1
    function proofToChain(string memory data) public{
        proofList[numProofs++] = data;
    }
    function uidToChain(string memory data) public{
        uidList[numUID++] = data;
    }
    function didToChain(string [] memory data, uint size1, uint size2) public{
        DID memory did;
        did.id = data[0];
        did.controller = data[1];
        uint sizeofmethod = size1;
        uint sizeofass = size2;
        string[] memory s = new string[](sizeofmethod);
        for(uint i = 0;i<sizeofmethod;i++){
            s[i] = data[2+i];
        }
        string[] memory s1 = new string[](sizeofass);
        for(uint i = 0;i<sizeofass;i++){
            s1[i] = data[2+sizeofass+i];
        }       
        did.verificationMethod = s;
        did.assertionMethod = s1;
        didList.push(did);
        numofdid++;
    }
   
     //获取proof证明信息
    function getProofInformation(uint num) public view returns(string memory){
        string memory data = "0";
        if(num>=numProofs){
            return data;
        }
        else{
            data = proofList[num];
            return data;
        }
    }
    //获取uid信息
    function getUidInformation(uint num) public view returns(string memory){
        string memory data = "0";
        if(num>=numUID){
            return data;
        }
        else{
            data = uidList[num];
            return data;
        }
    }
    //获取did个数
    function getNumOfDid() public view returns(uint){
        return numofdid;
    }
    //获取proof个数
    function getNumOfproof() public view returns(uint){
        return numProofs;
    }
    //获取uid个数
    function getNumOfuid() public view returns(uint){
        return numUID;
    }

}
