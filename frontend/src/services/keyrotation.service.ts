import apiClient from './api.service';
import { VaultService } from './vault.service';
import ClientCryptoService from './crypto.service';

export class KeyRotationService {
  /**
   * Change master password and re-encrypt all vault data
   */
  static async changeMasterPassword(
    email: string,
    currentPassword: string,
    newPassword: string
  ): Promise<void> {
    try {
      console.log('🔄 [KeyRotation] Starting master password change...');
      
      // Step 1: Get current salt
      console.log('📝 [KeyRotation] Step 1: Getting current salt...');
      const saltResponse = await apiClient.post('/auth/get-salt', { email });
      const currentSalt = saltResponse.data.data.salt;
      
      // Step 2: Derive current keys to verify password
      console.log('🔐 [KeyRotation] Step 2: Deriving current keys...');
      const currentKeys = await ClientCryptoService.deriveMasterKeys(
        currentPassword,
        currentSalt
      );
      const currentAuthKeyHash = await ClientCryptoService.hashAuthKey(currentKeys.authKey);
      
      // Step 3: Get current DEK
      console.log('🔓 [KeyRotation] Step 3: Getting current encrypted DEK...');
      const userResponse = await apiClient.get('/auth/user-keys');
      const { encryptedDEK: currentEncryptedDEK, dekIV: currentDekIV } = userResponse.data.data;
      
      // Step 4: Decrypt current DEK with current encryption key
      console.log('🔓 [KeyRotation] Step 4: Decrypting current DEK...');
      const currentDEK = await ClientCryptoService.decryptDEK(
        {
          ciphertext: currentEncryptedDEK,
          iv: currentDekIV
        },
        currentKeys.encryptionKey
      );
      
      // Step 5: Get all vault items
      console.log('📦 [KeyRotation] Step 5: Loading all vault items...');
      const allItems = await VaultService.getVaultItems(currentDEK);
      console.log(`✅ [KeyRotation] Loaded ${allItems.length} vault items`);
      
      // Step 6: Generate new salt and derive new keys
      console.log('🔑 [KeyRotation] Step 6: Generating new keys...');
      const newSalt = ClientCryptoService.generateSalt();
      const newKeys = await ClientCryptoService.deriveMasterKeys(newPassword, newSalt);
      const newAuthKeyHash = await ClientCryptoService.hashAuthKey(newKeys.authKey);
      
      // Step 7: Generate new DEK
      console.log('🔑 [KeyRotation] Step 7: Generating new DEK...');
      const newDEK = await ClientCryptoService.generateDEK();
      const newEncryptedDEK = await ClientCryptoService.encryptDEK(newDEK, newKeys.encryptionKey);
      
      // Step 8: Re-encrypt all vault items with new DEK
      console.log('🔄 [KeyRotation] Step 8: Re-encrypting vault items...');
      const reEncryptedItems = await Promise.all(
        allItems.map(async (item) => {
          const dataToEncrypt = {
            title: item.title,
            username: item.username,
            password: item.password,
            url: item.url,
            notes: item.notes,
            customFields: item.customFields
          };
          
          const encrypted = await ClientCryptoService.encryptObject(dataToEncrypt, newDEK);
          
          return {
            id: item.id,
            name: item.title,
            encryptedData: encrypted.ciphertext,
            iv: encrypted.iv,
            category: item.category,
            favorite: item.favorite,
            tags: item.tags
          };
        })
      );
      
      // Step 9: Send everything to server for atomic update
      console.log('📤 [KeyRotation] Step 9: Sending to server...');
      await apiClient.post('/auth/rotate-keys', {
        currentAuthKeyHash,
        newAuthKeyHash,
        newSalt,
        newEncryptedDEK: newEncryptedDEK.ciphertext,
        newDekIV: newEncryptedDEK.iv,
        reEncryptedItems
      });
      
      console.log('✅ [KeyRotation] Master password changed successfully!');
    } catch (error: any) {
      console.error('❌ [KeyRotation] Error:', error);
      throw new Error(error.response?.data?.message || 'Không thể thay đổi master password');
    }
  }
}
