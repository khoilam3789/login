import { Router } from 'express';
import { VaultController } from '../controllers/vault.controller';

const router = Router();

// GET /api/v1/vault - Get all vault items
router.get('/', VaultController.getItems);

// GET /api/v1/vault/stats - Get vault statistics
router.get('/stats', VaultController.getStats);

// GET /api/v1/vault/:id - Get single vault item
router.get('/:id', VaultController.getItem);

// POST /api/v1/vault - Create new vault item
router.post('/', VaultController.createItem);

// PUT /api/v1/vault/:id - Update vault item
router.put('/:id', VaultController.updateItem);

// DELETE /api/v1/vault/:id - Delete vault item
router.delete('/:id', VaultController.deleteItem);

// PATCH /api/v1/vault/:id/favorite - Toggle favorite status
router.patch('/:id/favorite', VaultController.toggleFavorite);

export default router;
