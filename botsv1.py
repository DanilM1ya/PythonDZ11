import pandas as pd
import matplotlib.pyplot as plt
import json

print("Анализирую логи")

#Загружаем данные
with open('botsv1.json', 'r', encoding='utf-8') as file:
    data = json.load(file)

#Собираем логи
win = []
dns = []

for item in data:
    if 'result' in item:
        e = item['result']
        if e.get('EventCode') == 'DNS':
            dns.append(e)
        elif e.get('EventCode'):
            win.append(e)

df_win = pd.DataFrame(win)
df_dns = pd.DataFrame(dns)

print(f"Windows: {len(df_win)}, DNS: {len(df_dns)}")

#Считаем события в Windows
print("\nОпасные события Windows:")
dangerous = ['4624', '4625', '4672','4703', '4688', '4689', '4720', '4740', '4771']
designations = {
    '4703': 'Изменение прав',
    '4689': 'Завершение процесса',
    '4688': 'Создание процесса',
    '4624': 'Успешный вход',
    '4625': 'Неудачный вход',
    '4672': 'Особые права',
    '4720': 'Новый пользователь',
    '4740': 'Блокировка',
    '4771': 'Ошибка входа'
}

problems = []
for id in dangerous:
    quantity = len(df_win[df_win['EventCode'] == id])
    if quantity > 0:
        problems.append({
            'text': f"{designations[id]} ({id})",
            'count': quantity,
            'color': 'red'
        })
        print(f"  {designations[id]}: {quantity}")

#Считаем подозрительные DNS
print("\nПодозрительные DNS:")
if len(df_dns) > 0:
    for domain in df_dns['QueryName']:
        domain = str(domain).lower()
        suspiciously = False
        reasons = []
        
        # 1. Подозрительные слова
        if 'malicious' in domain or 'c2' in domain or 'evil' in domain:
            suspiciously = True
            reasons.append('подозрительное название домена')
        
        # 2. Слишком длинный (> 30 символов)
        if len(domain) > 30:
            suspiciously = True
            reasons.append('длинный')
        
        # 3. Много цифр (больше 5)
        digits = sum(c.isdigit() for c in domain)
        if digits > 5:
            suspiciously = True
            reasons.append(f'цифр:{digits}')
        
        # 4. Много точек (много поддоменов)
        if domain.count('.') > 3:
            suspiciously = True
            reasons.append('много точек')

        # Добавляем в список problems
        if suspiciously:
            problems.append({
                'text': f"DNS: {domain} ({', '.join(reasons)})",
                'count': 1,
                'color': 'blue'
            })
            print(f"  {domain} ({', '.join(reasons)})")

#Берем топ-10
top = sorted(problems, key=lambda x: x['count'], reverse=True)[:10]

print("\nТоп-10 проблем:")
for i, p in enumerate(top, 1):
    print(f"{i}. {p['text']} - {p['count']}")

#Простой график
plt.figure(figsize=(10, 10))
plt.bar([p['text'] for p in top], [p['count'] for p in top], 
        color=[p['color'] for p in top])
plt.xticks(rotation=45, ha='right')
plt.title('Топ проблем безопасности')
plt.tight_layout()
plt.savefig('График.png')
plt.show()

print("\nГотово! Результаты сохранены в файл График.png")