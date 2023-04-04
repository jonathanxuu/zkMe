import { expect } from "chai";
import { Contract } from "ethers";
import { ethers } from "hardhat";

describe("Converter", function () {
  let Converter, converter: Contract;
  let libCredential, libCredentialObj;
  let libAttestation, libAttestationObj;
  let ctypeRegistry, ctypeRegistryObj: Contract;
  const FieldType = {
    BOOL: 0,
    STRING: 1,
    UINT: 2,
    UINT8: 3,
    UINT16: 4,
    UINT32: 5,
    UINT64: 6,
    UINT128: 7,
    UINT256: 8,
    INT: 9,
    INT8: 10,
    INT16: 11,
    INT32: 12,
    INT64: 13,
    INT128: 14,
    INT256: 15,
    ARRAY: 16,
    ADDRESS: 17
  };

  before(async function () {
    libCredential = await ethers.getContractFactory("libCredential");
    libCredentialObj = await libCredential.deploy();
    await libCredentialObj.deployed();

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
      }
    });
    converter = await Converter.deploy(ctypeRegistryObj.address);
    await converter.deployed();

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
      expect(getctype.fieldData).to.have.members(["name", "age"]);
      expect(getctype.fieldType).to.have.members([FieldType.STRING, FieldType.UINT]);

    });
  });

  describe("Converter", function () {
    it("Register CType & make Attestation Convertion Successfully", async () => {
      await ctypeRegistryObj.register(
        [["name", "age"], [FieldType.STRING, FieldType.UINT]],
        "0x824c9cd9f7fe36c33a2ded2c4b17be4b0d8a159f57baa193213e7365be1118bd"
      );
      await expect(converter.convertToAttestation(
        ["0x0001", "0x824c9cd9f7fe36c33a2ded2c4b17be4b0d8a159f57baa193213e7365be1118bd", "0xcf3b4cc5e36b30661a82cf1f8583a1761dddf155583b3e6996b5b37ca505e2c7", "0x3f209f25b1594a778f0f65522e5d53c7bc7ae78923418b45472e02bb361629e4", ["0x867a436c6f616b", "0x13"], "0x57E7b664aaa7C895878DdCa5790526B9659350Ec", "0x11f8b77F34FCF14B7095BF5228Ac0606324E82D1", "1680231693549", "0", "0x376906efdf298d1984663c186577811b34a0921f7014ee4a30244644e1156e16136065e53e3785f545e5617a589c3886dc73ea98486becd9f9cf721bdd06db2500"])
      ).emit(converter, "ConvertSuccess");
    })
  })
});
