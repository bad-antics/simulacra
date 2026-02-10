"""Simulacra & Simulation Engine"""
import json,random

class SimulacraEngine:
    ORDERS_OF_SIMULACRA={
        1:{"name":"Faithful Copy","era":"Pre-modern","description":"Image reflects basic reality",
           "example":"Religious icons, maps","relationship":"Representation"},
        2:{"name":"Perverted Copy","era":"Industrial","description":"Image masks and perverts reality",
           "example":"Mass production, photography","relationship":"Maleficence"},
        3:{"name":"No Relation","era":"Postmodern","description":"Image masks the absence of reality",
           "example":"Disneyland, shopping malls","relationship":"Sorcery"},
        4:{"name":"Pure Simulacrum","era":"Hypermodern","description":"Image has no relation to reality",
           "example":"Social media, virtual worlds","relationship":"Simulation"},
    }
    
    def analyze_order(self,order):
        return self.ORDERS_OF_SIMULACRA.get(order,{})
    
    def classify_media(self,media_description):
        keywords_to_order={
            4:["virtual","metaverse","deepfake","ai_generated","filter","avatar"],
            3:["brand","theme_park","reality_tv","influencer","staged"],
            2:["photograph","film","advertisement","mass_produced","copy"],
            1:["painting","sculpture","handmade","original","authentic"],
        }
        desc_lower=media_description.lower()
        for order,keywords in keywords_to_order.items():
            if any(k in desc_lower for k in keywords):
                return {"order":order,**self.ORDERS_OF_SIMULACRA[order]}
        return {"order":3,"note":"Default: postmodern condition"}
    
    def hyperreality_index(self,factors):
        """Calculate hyperreality score from environmental factors"""
        score=0
        if factors.get("media_saturation"): score+=20
        if factors.get("consumerism"): score+=15
        if factors.get("theme_environments"): score+=15
        if factors.get("social_media_presence"): score+=20
        if factors.get("virtual_experiences"): score+=20
        if factors.get("ai_content"): score+=10
        return {"index":min(score,100),"phase":"Hyperreal" if score>70 else "Transitional" if score>40 else "Real"}
