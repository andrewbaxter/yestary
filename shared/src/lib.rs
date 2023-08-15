use chrono::{
    DateTime,
    Utc,
};
use serde::{
    Deserialize,
    Serialize,
};

#[derive(Serialize, Deserialize)]
pub struct SerialStamp {
    pub hash: String,
    pub stamp: DateTime<Utc>,
}
