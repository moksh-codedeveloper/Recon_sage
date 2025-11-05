import httpx, datetime, asyncio
from .json_logger import JSONLogger

class Scanner:
    def __init__(self, target, wordlist_1, wordlist_2, json_file_name, json_file_path):
        self.target = target
        self.wordlist_1 = wordlist_1
        self.wordlist_2 = wordlist_2
        self.json_file_name = json_file_name
        self.json_file_path = json_file_path

    def extract_words_from_wordlist(self, wordlist):
        data = []
        with open(wordlist, "r", encoding='utf-8') as f:
            for words in f:
                s = words.strip()
                if s :
                    data.append(s)
        
        return data
    
    def now_iso(self):
        return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    async def run_scan(self):
        pass