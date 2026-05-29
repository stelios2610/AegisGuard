content = open('web/templates/vpn_new_content.txt','r',encoding='utf-8').read()
open('web/templates/vpn.html','w',encoding='utf-8').write(content)
print('Done')
