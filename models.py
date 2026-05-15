from pydantic import BaseModel, ConfigDict
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
    model_config = ConfigDict(extra='allow')
    
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
    
    # Custom Firewall / Check Point fields
    log_link: Optional[str] = None
    xlatesrc: Optional[str] = None
    xlatesport: Optional[str] = None
    xlatedst: Optional[str] = None
    xlatedport: Optional[str] = None
    service_id: Optional[str] = None
    src: Optional[str] = None
    service: Optional[str] = None
    s_port: Optional[str] = None
    proto: Optional[str] = None
    product: Optional[str] = None
    outzone: Optional[str] = None
    nat_rulenum: Optional[str] = None
    nat_addtnl_rulenum: Optional[str] = None
    rule_uid: Optional[str] = None
    rule_name: Optional[str] = None
    rule_action: Optional[str] = None
    parent_rule: Optional[str] = None
    match_id: Optional[str] = None
    layer_uuid: Optional[str] = None
    layer_name: Optional[str] = None
    loguid: Optional[str] = None


class WebhookResponse(BaseModel):
    status: str
    message: Optional[str] = None
