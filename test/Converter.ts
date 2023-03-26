import { expect } from "chai";
import { ethers } from "hardhat";

describe("Converter", function () {
  let Converter,myContract;
  let libCredential,libCredentialObj;
  let libAttestation,libAttestationObj;
  let libRevocation,libRevocationObj;

  before(async function(){
    libCredential = await ethers.getContractFactory("libCredential");
    libCredentialObj = await libCredential.deploy();

    libRevocation = await ethers.getContractFactory("libRevocation");
    libRevocationObj = await libRevocation.deploy();

    libAttestation = await ethers.getContractFactory("libAttestation",{libraries:{libCredential : libCredentialObj.address}});
    libAttestationObj = await libAttestation.deploy();

    Converter = await ethers.getContractFactory("Converter", {
      libraries: {
        libCredential: libCredentialObj.address,
        libAttestation: libAttestationObj.address,
        libRevocation: libRevocationObj.address,
      }
    });
    myContract = await Converter.deploy();
  });
  describe("Deployment", function() {
    it("test wait to add", async ()=> {
        expect(1).to.equal(1);
    });
  });
  });
