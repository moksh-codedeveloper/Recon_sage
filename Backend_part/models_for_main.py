from pydantic import BaseModel 

class FalseDetectorModel(BaseModel):
    target:str
    json_file_name:str
    json_full_path:str
    timeout:int
    concurrency:int
    json_file_to_read:str
    list_of_targets:list


class WafModel(BaseModel):
    target:str
    wordlist:list
    json_file_name:str
    json_file_path:str
    concurrency:int
    timeout:int

class RateLimit(BaseModel):
    target: str
    timeout: int
    concurrency: int
    json_file_name: str
    json_file_path: str
    domains : list
    user_paths:list

class Target(BaseModel):
    target: str
    wordlist: str
    wordlist_2: str
    json_file_path: str
    json_file_name: str
    concurrency: int
    timeout: int
