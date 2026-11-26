WITH entity_collisions AS (
  SELECT entity_id
  FROM samples
  GROUP BY entity_id
  HAVING COUNT(DISTINCT split) > 1
), payload_collisions AS (
  SELECT content_sha256
  FROM samples
  GROUP BY content_sha256
  HAVING COUNT(DISTINCT split) > 1
), findings AS (
  SELECT 'shared_entity' AS check_name, row_id, split, entity_id AS detail
    FROM samples JOIN entity_collisions USING (entity_id)
  UNION ALL
  SELECT 'shared_payload', row_id, split, content_sha256
    FROM samples JOIN payload_collisions USING (content_sha256)
  UNION ALL
  SELECT 'undeclared_source', s.row_id, s.split, s.source_id
    FROM samples AS s
    LEFT JOIN registry AS r USING (source_id)
    WHERE r.source_id IS NULL
  UNION ALL
  SELECT 'future_feature', row_id, split, feature_max_at
    FROM samples WHERE feature_max_at > cutoff_at
  UNION ALL
  SELECT 'label_predates_cutoff', row_id, split, label_ready_at
    FROM samples WHERE label_ready_at < cutoff_at
  UNION ALL
  SELECT 'label_unavailable_at_freeze', row_id, split, label_ready_at
    FROM samples
    WHERE (split = 'train' AND label_ready_at > :train_end)
       OR (split = 'validation' AND label_ready_at > :val_end)
  UNION ALL
  SELECT 'cutoff_outside_partition', row_id, split, cutoff_at
    FROM samples
    WHERE (split = 'train' AND cutoff_at > :train_end)
       OR (split = 'validation' AND (cutoff_at <= :train_end OR cutoff_at > :val_end))
       OR (split = 'test' AND cutoff_at <= :val_end)
)
SELECT * FROM findings ORDER BY check_name, split, row_id;

