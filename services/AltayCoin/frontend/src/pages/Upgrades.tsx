import { JSX, useEffect, useState } from "react";
import Mouse from "/public/upgrades/devices/mouse.png"
import Keybord from "/public/upgrades/devices/keybord.png"
import Monitor from "/public/upgrades/devices/monitor.png"
import Kreslo from "/public/upgrades/devices/kreslo.png"
import CPU from "/public/upgrades/devices/cpu.png"
import Videocard from "/public/upgrades/devices/videocard.png"
import Proc from "/public/upgrades/devices/proc.png"
import Hydra from "/public/upgrades/programs/hydra.png"
import Burp from "/public/upgrades/programs/burp.png"
import Sqlmap from "/public/upgrades/programs/sqlmap.png"
import Wireshark from "/public/upgrades/programs/wireshark.png"
import Nmap from "/public/upgrades/programs/nmap.png"
import Hashcat from "/public/upgrades/programs/hashcat.png"
import Nicto from "/public/upgrades/programs/nicto.png"
import Metasploit from "/public/upgrades/programs/metasploit.png"
import Radare2 from "/public/upgrades/programs/radare2.png"
import Netcat from "/public/upgrades/programs/netcat.png"
import Mainer from "/public/upgrades/posive/maining.png"
import Scam from "/public/upgrades/posive/scam.png"
import Tor from "/public/upgrades/posive/tor.png"
import Fishing from "/public/upgrades/posive/fishing.png"
import Reket from "/public/upgrades/posive/reket.png"
import Backdoor from "/public/upgrades/posive/backdoor.png"
import Carding from "/public/upgrades/posive/carding.png"
import axios from "axios";

const Earn: React.FC = () => {
  const [activeCategory, setActiveCategory] = useState<string>("devices");

  const [mouse, setMouse] = useState<number[]>([0,1,100 ])
  const [keyboard, setKeyboard] = useState<number[]>([0,2,100])
  const [monitor, setMonitor] = useState<number[]>([0,3,100])
  const [kreslo, setKreslo] = useState<number[]>([0,2,100])
  const [cpu, setCpu] = useState<number[]>([0,200,100])
  const [videocard, setVideocard] = useState<number[]>([0,100,100])
  const [proc, setProc] = useState<number[]>([0,300,100])
  const [hydra, setHydra] = useState<number[]>([0,1,100])
  const [burp, setBurp] = useState<number[]>([0,1,100])
  const [sqlmap, setSqlmap] = useState<number[]>([0,1,100])
  const [wireshark, setWireshark] = useState<number[]>([0,1,100])
  const [nmap, setNmap] = useState<number[]>([0,1,100])
  const [hashcat, setHashcat] = useState<number[]>([0,1,100])
  const [nicto, setNicto] = useState<number[]>([0,1,100])
  const [metasploit, setMetasploit] = useState<number[]>([0,1,100])
  const [radare2, setRadare2] = useState<number[]>([0,1,100])
  const [netcat, setNetcat] = useState<number[]>([0,1,100])
  const [mainer, setMainer] = useState<number[]>([0,1,100])
  const [scam, setScam] = useState<number[]>([0,1,100])
  const [darknet, setDarknet] = useState<number[]>([0,1,100])
  const [fishing, setFishing] = useState<number[]>([0,1,100])
  const [reket, setReket] = useState<number[]>([0,1,100])
  const [backdoor, setBackdoor] = useState<number[]>([0,1,100])
  const [carding, setCarding] = useState<number[]>([0,1,100])

  const getUpgrades: () => void = async () =>{
    try {
      const response = await axios.get(`http://${window.location.hostname}:8080/users/upgrades`, {
        headers: {
          Authorization: `${localStorage.getItem("token")}`,
        },
      })
      if(response.data.success){
        setMouse(response.data.data.rows[0].value.upgrades[0].mouse)
        setKeyboard(response.data.data.rows[0].value.upgrades[0].keyboard)
        setMonitor(response.data.data.rows[0].value.upgrades[0].monitor)
        setKreslo(response.data.data.rows[0].value.upgrades[0].kreslo)
        setCpu(response.data.data.rows[0].value.upgrades[0].cpu)
        setVideocard(response.data.data.rows[0].value.upgrades[0].videocard)
        setProc(response.data.data.rows[0].value.upgrades[0].proc)
        setHydra(response.data.data.rows[0].value.upgrades[1].hydra)
        setBurp(response.data.data.rows[0].value.upgrades[1].burp)
        setSqlmap(response.data.data.rows[0].value.upgrades[1].sqlmap)
        setWireshark(response.data.data.rows[0].value.upgrades[1].wireshark)
        setNmap(response.data.data.rows[0].value.upgrades[1].nmap)
        setHashcat(response.data.data.rows[0].value.upgrades[1].hashcat)
        setNicto(response.data.data.rows[0].value.upgrades[1].nicto)
        setMetasploit(response.data.data.rows[0].value.upgrades[1].metasploit)
        setRadare2(response.data.data.rows[0].value.upgrades[1].radare2)
        setNetcat(response.data.data.rows[0].value.upgrades[1].netcat)
        setMainer(response.data.data.rows[0].value.upgrades[2].mainer)
        setScam(response.data.data.rows[0].value.upgrades[2].scam)
        setDarknet(response.data.data.rows[0].value.upgrades[2].darknet)
        setFishing(response.data.data.rows[0].value.upgrades[2].fisching)
        setReket(response.data.data.rows[0].value.upgrades[2].reket)
        setBackdoor(response.data.data.rows[0].value.upgrades[2].backdoor)
        setCarding(response.data.data.rows[0].value.upgrades[2].carding)
      } else{
      }
    } catch (error) {
    }
  }
  useEffect(() => {
    getUpgrades();
  }, []);

  async function upgrade(event: React.MouseEvent<HTMLButtonElement>) {
    const parentDiv = event.currentTarget.closest("div");
    if (parentDiv) {
        const response = await axios.post(`http://${window.location.hostname}:8080/users/upgrade/${parentDiv.id}`,{}, {
            headers: {
              Authorization: `${localStorage.getItem("token")}`,
            },
          })
        if(response.data.success){
            getUpgrades();
        }
        else{
            alert(`Ошибка: ${response.data.message}`)
        }
    }
  }

  const upgradesContent: Record<string, JSX.Element> = {
    devices: <>
    <div id="mouse" className="card">
        <img alt="" src={Mouse} draggable="false"></img>
        <div>
            <span>Мышь</span>
        </div>
        <div>
            <span>{mouse[0]}</span><span> e/s &gt;&gt; </span><span>{mouse[1]}</span><span> e/s</span>
        </div>
        <button onClick={upgrade}>{mouse[2]} AC</button>
    </div>
    <div id="keyboard" className="card">
        <img alt="" src={Keybord} draggable="false"></img>
        <div>
            <span>Клавиатура</span>
        </div>
        <div>
            <span>{keyboard[0]}</span><span> e/s &gt;&gt; </span><span>{keyboard[1]}</span><span> e/s</span>
        </div>
        <button onClick={upgrade}>{keyboard[2]} AC</button>
    </div>
    <div id="monitor" className="card">
        <img alt="" src={Monitor} draggable="false"></img>
        <div>
            <span>Монитор</span>
        </div>
        <div>
            <span>{monitor[0]}</span><span> e/s &gt;&gt; </span><span>{monitor[1]}</span><span> e/s</span>
        </div>
        <button onClick={upgrade}>{monitor[2]} AC</button>
    </div>
    <div id="kreslo" className="card">
        <img alt="" src={Kreslo} draggable="false"></img>
        <div>
            <span>Кресло</span>
        </div>
        <div>
            <span>{kreslo[0]}</span><span> e/s &gt;&gt; </span><span>{kreslo[1]}</span><span> e/s</span>
        </div>
        <button onClick={upgrade}>{kreslo[2]} AC</button>
    </div>
    <div id="cpu" className="card">
        <img alt="" src={CPU} draggable="false"></img>
        <div>
            <span>Оперативная память</span>
        </div>
        <div>
            <span>{cpu[0]}</span><span> maxE &gt;&gt; </span><span>{cpu[1]}</span><span> maxE</span>
        </div>
        <button onClick={upgrade}>{cpu[2]} AC</button>
    </div>
    <div id="videocard" className="card">
        <img alt="" src={Videocard} draggable="false"></img>
        <div>
            <span>Видеокарта</span>
        </div>
        <div>
            <span>{videocard[0]}</span><span> maxE &gt;&gt; </span><span>{videocard[1]}</span><span> maxE</span>
        </div>
        <button onClick={upgrade}>{videocard[2]} AC</button>
    </div>
    <div id="proc" className="card">
        <img alt="" src={Proc} draggable="false"></img>
        <div>
            <span>Процессор</span>
        </div>
        <div>
            <span>{proc[0]}</span><span> maxE &gt;&gt; </span><span>{proc[1]}</span><span> maxE</span>
        </div>
        <button onClick={upgrade}>{proc[2]} AC</button>
    </div>
    </>,
    programs: <>
    <div id="hydra" className="card">
        <img alt="" src={Hydra} draggable="false"></img>
        <div>
            <span>Hydra</span>
        </div>
        <div>
            <span>{hydra[0]}</span><span> AC/click &gt;&gt; </span><span>{hydra[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{hydra[2]} AC</button>
    </div>
    <div id="burp" className="card">
        <img alt="" src={Burp} draggable="false"></img>
        <div>
            <span>Burp</span>
        </div>
        <div>
            <span>{burp[0]}</span><span> AC/click &gt;&gt; </span><span>{burp[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{burp[2]} AC</button>
    </div>
    <div id="sqlmap" className="card">
        <img alt="" src={Sqlmap} draggable="false"></img>
        <div>
            <span>SQLmap</span>
        </div>
        <div>
            <span>{sqlmap[0]}</span><span> AC/click &gt;&gt; </span><span>{sqlmap[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{sqlmap[2]} AC</button>
    </div>
    <div id="wireshark" className="card">
        <img alt="" src={Wireshark} draggable="false"></img>
        <div>
            <span>Wireshark</span>
        </div>
        <div>
            <span>{wireshark[0]}</span><span> AC/click &gt;&gt; </span><span>{wireshark[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{wireshark[2]} AC</button>
    </div>
    <div id="nmap" className="card">
        <img alt="" src={Nmap} draggable="false"></img>
        <div>
            <span>Nmap</span>
        </div>
        <div>
            <span>{nmap[0]}</span><span> AC/click &gt;&gt; </span><span>{nmap[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{nmap[2]} AC</button>
    </div>
    <div id="hashcat" className="card">
        <img alt="" src={Hashcat} draggable="false"></img>
        <div>
            <span>Hashcat</span>
        </div>
        <div>
            <span>{hashcat[0]}</span><span> AC/click &gt;&gt; </span><span>{hashcat[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{hashcat[2]} AC</button>
    </div>
    <div id="nicto" className="card">
        <img alt="" src={Nicto} draggable="false"></img>
        <div>
            <span>Nicto</span>
        </div>
        <div>
            <span>{nicto[0]}</span><span> AC/click &gt;&gt; </span><span>{nicto[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{nicto[2]} AC</button>
    </div>
    <div id="metasploit" className="card">
        <img alt="" src={Metasploit} draggable="false"></img>
        <div>
            <span>Metasploit</span>
        </div>
        <div>
            <span>{metasploit[0]}</span><span> AC/click &gt;&gt; </span><span>{metasploit[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{metasploit[2]} AC</button>
    </div>
    <div id="radare2" className="card">
        <img alt="" src={Radare2} draggable="false"></img>
        <div>
            <span>Radare2</span>
        </div>
        <div>
            <span>{radare2[0]}</span><span> AC/click &gt;&gt; </span><span>{radare2[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{radare2[2]} AC</button>
    </div>
    <div id="netcat" className="card">
        <img alt="" src={Netcat} draggable="false"></img>
        <div>
            <span>Netcat</span>
        </div>
        <div>
            <span>{netcat[0]}</span><span> AC/click &gt;&gt; </span><span>{netcat[1]}</span><span> AC/click</span>
        </div>
        <button onClick={upgrade}>{netcat[2]} AC</button>
    </div>
    </>,
    passive: <>
    <div id="mainer" className="card">
        <img alt="" src={Mainer} draggable="false"></img>
        <div>
            <span>Майнер</span>
        </div>
        <div>
            <span>{mainer[0]}</span><span> AC/s &gt;&gt; </span><span>{mainer[1]}</span><span> AC/s</span>
        </div>
        <button onClick={upgrade}>{mainer[2]} AC</button>
    </div>
    <div id="scam" className="card">
        <img alt="" src={Scam} draggable="false"></img>
        <div>
            <span>Скам</span>
        </div>
        <div>
            <span>{scam[0]}</span><span> AC/s &gt;&gt; </span><span>{scam[1]}</span><span> AC/s</span>
        </div>
        <button onClick={upgrade}>{scam[2]} AC</button>
    </div>
    <div id="darknet" className="card">
        <img alt="" src={Tor} draggable="false"></img>
        <div>
            <span>DarkNet</span>
        </div>
        <div>
            <span>{darknet[0]}</span><span> AC/s &gt;&gt; </span><span>{darknet[1]}</span><span> AC/s</span>
        </div>
        <button onClick={upgrade}>{darknet[2]} AC</button>
    </div>
    <div id="fisching" className="card">
        <img alt="" src={Fishing} draggable="false"></img>
        <div>
            <span>Фишинг</span>
        </div>
        <div>
            <span>{fishing[0]}</span><span> AC/s &gt;&gt; </span><span>{fishing[1]}</span><span> AC/s</span>
        </div>
        <button onClick={upgrade}>{fishing[2]} AC</button>
    </div>
    <div id="reket" className="card">
        <img alt="" src={Reket} draggable="false"></img>
        <div>
            <span>Рэкет</span>
        </div>
        <div>
            <span>{reket[0]}</span><span> AC/s &gt;&gt; </span><span>{reket[1]}</span><span> AC/s</span>
        </div>
        <button onClick={upgrade}>{reket[2]} AC</button>
    </div>
    <div id="backdoor" className="card">
        <img alt="" src={Backdoor} draggable="false"></img>
        <div>
            <span>Бэкдор</span>
        </div>
        <div>
            <span>{backdoor[0]}</span><span> AC/s &gt;&gt; </span><span>{backdoor[1]}</span><span> AC/s</span>
        </div>
        <button onClick={upgrade}>{backdoor[2]} AC</button>
    </div>
    <div id="carding" className="card">
        <img alt="" src={Carding} draggable="false"></img>
        <div>
            <span>Майнинг банковских карт</span>
        </div>
        <div>
            <span>{carding[0]}</span><span> AC/s &gt;&gt; </span><span>{carding[1]}</span><span> AC/s</span>
        </div>
        <button onClick={upgrade}>{carding[2]} AC</button>
    </div>
    </>,
  };

  return (
    <>
      <div className="upgradesNav">
        <span 
          className={activeCategory === "devices" ? "active" : ""} 
          onClick={() => setActiveCategory("devices")}
        >
          Девайсы
        </span>

        <span 
          className={activeCategory === "programs" ? "active" : ""} 
          onClick={() => setActiveCategory("programs")}
        >
          Программы
        </span>

        <span 
          className={activeCategory === "passive" ? "active" : ""} 
          onClick={() => setActiveCategory("passive")}
        >
          Пасивный доход
        </span>
      </div>

      <div className="upgrades">
        {upgradesContent[activeCategory]}
      </div>
    </>
  );
};

export default Earn;