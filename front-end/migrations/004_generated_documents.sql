-- ============================================================================
-- CLINIC-IN-A-BOX: Generated Documents Table
-- ============================================================================
-- This table stores references to generated security assessment documents
-- (NESSUS, ZAP, NMAP scans) for each profile.
-- ============================================================================

-- Enable UUID extension if not already enabled
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create the generated_documents table
CREATE TABLE IF NOT EXISTS generated_documents (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  profile_id UUID NOT NULL REFERENCES profiles(id) ON DELETE CASCADE,
  document_type VARCHAR(20) NOT NULL CHECK (document_type IN ('nessus', 'zap', 'nmap', 'combined')),
  filename VARCHAR(255) NOT NULL,
  content TEXT, -- Optional: store the actual content or just metadata
  file_path TEXT, -- Path to file on FTP/storage
  file_size INTEGER,
  metadata JSONB DEFAULT '{}', -- Additional metadata (hosts scanned, alert counts, etc.)
  generated_by UUID REFERENCES users(id),
  generated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  
  -- Ensure one document type per profile
  UNIQUE(profile_id, document_type)
);

-- Create indexes for common queries
CREATE INDEX IF NOT EXISTS idx_generated_docs_profile ON generated_documents(profile_id);
CREATE INDEX IF NOT EXISTS idx_generated_docs_type ON generated_documents(document_type);
CREATE INDEX IF NOT EXISTS idx_generated_docs_generated_at ON generated_documents(generated_at DESC);

-- Add comments
COMMENT ON TABLE generated_documents IS 'Stores generated security scan documents for clinic profiles';
COMMENT ON COLUMN generated_documents.document_type IS 'Type of document: nessus (vulnerability scan), zap (web app scan), nmap (network discovery)';
COMMENT ON COLUMN generated_documents.content IS 'Optional storage of document content directly in database';
COMMENT ON COLUMN generated_documents.file_path IS 'Path to external file storage (FTP, S3, etc.)';
COMMENT ON COLUMN generated_documents.metadata IS 'JSON metadata: hosts_scanned, alert_count, vulnerabilities_found, etc.';

-- Example query to check documents for a profile:
-- SELECT * FROM generated_documents WHERE profile_id = 'your-profile-uuid';

-- Example insert:
-- INSERT INTO generated_documents (profile_id, document_type, filename, metadata, generated_by)
-- VALUES ('profile-uuid', 'nessus', 'scan_company_123.nessus', '{"hosts_scanned": 15}', 'user-uuid');
