pub type Uuid = uuid::Uuid;

uniffi::custom_type!(Uuid, String, {
    remote,
    lower: |uuid: Uuid| uuid.to_string(),
    try_lift: |value: String| Ok(uuid::Uuid::parse_str(&value)?),
});
