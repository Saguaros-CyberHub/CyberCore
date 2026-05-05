/**
 * Migration 018: Add parent_module column to cybercore_module
 * 
 * Purpose: Support hierarchical module/plugin structure
 * - Modules can contain plugins
 * - Plugins reference their parent module via parent_module column
 */

-- Add parent_module column if it doesn't exist
ALTER TABLE cybercore_module
ADD COLUMN IF NOT EXISTS parent_module VARCHAR(255) DEFAULT NULL;

-- Add comment for documentation
COMMENT ON COLUMN cybercore_module.parent_module IS 'For plugins: reference to parent module key (e.g., ciab.parent_module = crucible)';
