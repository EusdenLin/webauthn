#! /usr/bin/env python3

import sys

from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time
class auto_fido:
	def __init__(self, exec_code):  
		chrome_options = Options()         
		chrome_options.add_argument('--headless')  # 啟動Headless 無頭        
		chrome_options.add_argument('--disable-gpu') #關閉GPU 避免某些系統或是網頁出錯        
		if exec_code == 1:
			driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=chrome_options)
		
		else:		    
			driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()))
        
		driver.get("http://localhost:5000")        
		element = driver.find_element(by='name', value='Username')        
		element.send_keys('eusden')        
		button = driver.find_element('id', 'but1')        
		button.click()        
		time.sleep(5)        
		driver.close()	

if __name__ == '__main__':
	print(sys.argv[0])
	if len(sys.argv) < 2:
		s1 = auto_fido(0)
	elif sys.argv[1] == 'headless':
		s1 = auto_fido(1)
	



