import os, configparser, datetime

class Config:

    @classmethod
    def properties(self, section, folder, property):
        config = configparser.RawConfigParser()
        config.read(os.getcwd().replace('\\', '/').replace(folder, '')+'/Config.txt')
        return config.get(section, property)
    
