#![cfg_attr(not(feature = "std"), no_std)]

use ink_lang as ink;

#[ink::contract]
mod verify_signature {

    #[ink(storage)]
    pub struct VerifySignature {
        signer: AccountId,
    }

    impl VerifySignature {
        #[ink(constructor)]
        pub fn new() -> Self {
            Self { signer: Self::env().caller() }
        }

        #[ink(message)]
        pub fn verify_signature(&self, data: u64, signature: [u8; 65]){
            let encodable = (self.env().account_id(), data);
            let mut message = <ink_env::hash::Sha2x256 as ink_env::hash::HashOutput>::Type::default();
            ink_env::hash_encoded::<ink_env::hash::Sha2x256, _>(&encodable, &mut message);

            let mut output = [0; 33];
            ink_env::ecdsa_recover(&signature, &message, &mut output);
            let pub_key = eth::ECDSAPublicKey::from(output);
            let signature_account_id = AccountId::from(pub_key.to_default_account_id());
            
            assert!(self.signer == signature_account_id, "invalid signature");
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        use ink_lang as ink;
        use hex_literal;
        use sp_core::Pair;
        use scale::Encode;

        fn default_accounts(
        ) -> ink_env::test::DefaultAccounts<ink_env::DefaultEnvironment> {
            ink_env::test::default_accounts::<ink_env::DefaultEnvironment>()
        }

        fn set_next_caller(caller: AccountId) {
            ink_env::test::set_caller::<ink_env::DefaultEnvironment>(caller);
        }

        fn contract_id() -> AccountId {
            let accounts = default_accounts();
            let contract_id = accounts.bob;
            ink_env::test::set_callee::<ink_env::DefaultEnvironment>(contract_id);
            contract_id
        }

        fn sign(contract_id: AccountId, data: u64) -> [u8; 65] {
            let encodable = (contract_id, data);
            let mut message = <ink_env::hash::Sha2x256 as ink_env::hash::HashOutput>::Type::default(); // 256-bit buffer
            ink_env::hash_encoded::<ink_env::hash::Sha2x256, _>(&encodable, &mut message);

            let seed = hex_literal::hex!("e5be9a5092b81bca64be81d212e7f2f9eba183bb7a90954f7b76361f6edb5c0a");
            let pair = sp_core::ecdsa::Pair::from_seed(&seed);
            let signature = pair.sign(&message).encode();
            let formatted : [u8; 65] = signature[..].try_into().expect("slice with incorrect length");
            formatted
        }

        #[ink::test]
        fn test_verify_signature() {
            let accounts = default_accounts();
            set_next_caller(accounts.alice);
            let verify_signature = VerifySignature::new();

            let contract_id = contract_id();
            let signature = sign(contract_id, 100);

            verify_signature.verify_signature(100, signature);
        }
    }
}
