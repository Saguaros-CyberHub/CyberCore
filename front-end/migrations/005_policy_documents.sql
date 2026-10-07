-- ============================================================================
-- CLINIC-IN-A-BOX: Add 'policies' document type
-- ============================================================================
-- Widens the document_type CHECK constraint on generated_documents to allow
-- storing auto-generated policy documents alongside scan documents.
-- ============================================================================

ALTER TABLE generated_documents
  DROP CONSTRAINT IF EXISTS generated_documents_document_type_check;

ALTER TABLE generated_documents
  ADD CONSTRAINT generated_documents_document_type_check
  CHECK (document_type IN ('nessus', 'zap', 'nmap', 'combined', 'policies'));
