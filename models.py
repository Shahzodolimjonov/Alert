from pydantic import BaseModel
from typing import Optional, List


class QRadarOffense(BaseModel):
    id: Optional[int] = None
    description: Optional[str] = None
    severity: Optional[int] = None
    status: Optional[str] = None
    source_address_ids: Optional[str] = None
    destination_address_ids: Optional[str] = None
    domain_id: Optional[int] = None
    offense_type: Optional[int] = None
    relevant_offense_ids: Optional[List[int]] = None
    source_count: Optional[int] = None
    destination_count: Optional[int] = None
    last_updated_time: Optional[int] = None
    start_time: Optional[int] = None
    event_count: Optional[int] = None
    flow_count: Optional[int] = None
    assigned_to: Optional[str] = None
    categories: Optional[List[str]] = None


class QRadarEvent(BaseModel):
    id: Optional[int] = None
    eventname: Optional[str] = None
    username: Optional[str] = None
    sourceip: Optional[str] = None
    destinationip: Optional[str] = None
    starttime: Optional[str] = None
    magnitude: Optional[int] = None
    devicetype: Optional[str] = None
    qid: Optional[int] = None
    logsourceid: Optional[int] = None


class WebhookResponse(BaseModel):
    status: str
    message: Optional[str] = None
