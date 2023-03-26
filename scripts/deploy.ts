import { ethers } from "hardhat";

async function main() {
  const libCredential = await ethers.getContractFactory("libCredential");
  const libCredentialObj = await libCredential.deploy();

  const libRevocation = await ethers.getContractFactory("libRevocation");
  const libRevocationObj = await libRevocation.deploy();

  const libAttestation = await ethers.getContractFactory("libAttestation",{libraries:{libCredential : libCredentialObj.address}});
  const libAttestationObj = await libAttestation.deploy();

  const Converter = await ethers.getContractFactory("Converter",{
    libraries:{
      libCredential: libCredentialObj.address,
      libAttestation: libAttestationObj.address,
      libRevocation: libRevocationObj.address,
    }
  }
  
  
  );
  const converter = await Converter.deploy();
}

// We recommend this pattern to be able to use async/await everywhere
// and properly handle errors.
main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
