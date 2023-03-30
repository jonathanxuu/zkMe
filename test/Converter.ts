import { expect } from "chai";
import { Contract } from "ethers";
import { ethers } from "hardhat";

describe("Converter", function () {
  let Converter, myContract;
  let libCredential, libCredentialObj;
  let libAttestation, libAttestationObj;
  let libRevocation, libRevocationObj;
  let ctypeRegistry, ctypeRegistryObj: Contract;
  const FieldType = {
    BOOL:0,
    STRING:1,
    UINT:2,
    UINT8:3,
    UINT16:4,
    UINT32:5,
    UINT64:6,
    UINT128:7,
    UINT256:8,
    INT:9,
    INT8:10,
    INT16:11,
    INT32:12,
    INT64:13,
    INT128:14,
    INT256:15,
    ARRAY:16,
    ADDRESS:17
  };

  before(async function () {
    libCredential = await ethers.getContractFactory("libCredential");
    libCredentialObj = await libCredential.deploy();
    await libCredentialObj.deployed();

    libRevocation = await ethers.getContractFactory("libRevocation");
    libRevocationObj = await libRevocation.deploy();
    await libRevocationObj.deployed();

    libAttestation = await ethers.getContractFactory("libAttestation");
    libAttestationObj = await libAttestation.deploy();
    await libAttestationObj.deployed();

    ctypeRegistry = await ethers.getContractFactory("CTypeRegistry");
    ctypeRegistryObj = await ctypeRegistry.deploy();
    await ctypeRegistryObj.deployed();

    Converter = await ethers.getContractFactory("Converter", {
      libraries: {
        libCredential: libCredentialObj.address,
        libAttestation: libAttestationObj.address,
        libRevocation: libRevocationObj.address,
      }
    });
    myContract = await Converter.deploy(ctypeRegistryObj.address);
    await myContract.deployed();

  });

  describe("CTypeRegistry", function () {
    it("Register & Get CType Successfully", async () => {
      await ctypeRegistryObj.register(
          [["name", "age"], [FieldType.STRING, FieldType.UINT]],
          "0xb159990a86e5a2b97d9a0f6b1f95b2678b8ae396f2ec73ae3f6d22d8dd1e1668"
        );

        await expect(
          ctypeRegistryObj.register(
            [["name", "age"], [FieldType.STRING, FieldType.UINT]],
          "0xb159990a86e5a2b97d9a0f6b1f95b2678b8ae396f2ec73ae3f6d22d8dd1e1668"
          )
        ).to.be.revertedWithCustomError(ctypeRegistryObj, `AlreadyExists`);

        const getctype = await ctypeRegistryObj.getCType(
          "0xb159990a86e5a2b97d9a0f6b1f95b2678b8ae396f2ec73ae3f6d22d8dd1e1668",
          "0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1"
        );
        expect( getctype.fieldData).to.have.members(["name", "age"]);
        expect ( getctype.fieldType).to.have.members([FieldType.STRING, FieldType.UINT]);
       
    });
  });
});
