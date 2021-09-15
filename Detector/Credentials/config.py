#!/usr/bin/env python3
from dataclasses import dataclass

@dataclass
class es:
    host: str = 'https://140.113.194.82:9200'
    cred: tuple = ('user', 'password')