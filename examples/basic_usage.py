from simulacra.core import SimulacraEngine
e=SimulacraEngine()
for order in [1,2,3,4]:
    info=e.analyze_order(order)
    print(f"Order {order}: {info['name']} ({info['era']}) - {info['example']}")
print(f"\nClassify 'metaverse avatar': {e.classify_media('metaverse avatar')}")
print(f"Hyperreality: {e.hyperreality_index({'media_saturation':True,'social_media_presence':True,'ai_content':True})}")
