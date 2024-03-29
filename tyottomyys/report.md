# Laajan sanomalehtiaineiston käyttäminen ilmiöiden historiallisen esiintymisen selvittämiseen

Kansalliskirjaston sanomalehtiarkisto on laaja, enimmäkseen OCR:llä digitoitu tekstikokoelma, joka sisältää Suomessa julkaistujen sanomalehtien numeroita ja artikkeleja. Jokaiseen lähdetiedostoon liittyy julkaisuajankohta. Se soveltuu laajuutensa puolesta hyvinkin summittaisiin analyyseihin; menetelmään sisältyvät satunnaiset (ei-systemaattiset) virhetekijät hukkuvat laajan aineiston kohinaan.

Toisaalta aineisto on niin laaja, että analyysin pitääkin olla melko yksinkertainen. IDA-palvelusta ladattu vuosien 1920-2000 aineisto on purettuna 112 gigatavua, jolloin mikä tahansa koko aineistoa koskeva operaatio vaatii paljon prosessointiaikaa ja enemmän keskusmuistia kuin useimmilla tutkijoilla on käytettävissään.

Tässä esimerkissä tiivistämme aineiston mahdollisimman pitkälle, minkä jälkeen sovellamme siihen tehokasta operaatiota, joka kuitenkin pystyy löytämään kohtalaisen hienovaraisesti semanttista läheisyyttä valitun hakutermin kanssa.

## Menetelmä

Word embedding, suomeksi joskus "sanaupotus", on piste vektoriavaruudessa joka vastaa jossain mielessä yhtä sanaa. Käyttöyhteydestä riippuen eri sanoja vastaavilla pisteillä on tietynlaisia yhteyksiä.

Kielitieteellisestä näkökulmasta voidaan ajatella että vektoriavaruuden ulottuvuudet vastaisivat joitain tunnettuja sanojen ominaisuuksia, esimerkiksi sanaluokka (kaikki verbit olisivat tässä ulottuvuudessa samassa kohdassa), luku (monikkosanat olisivat tässä ulottuvuudessa samassa kohdassa), valenssi (samanvalenssiset verbit olisivat samassa paikassa, muiden sanaluokkien sanat nollassa). Lisäksi voisi olla erilaisia merkitykseen liittyviä ulottuvuuksia. Tällaisessa avaruudessa sanat "peruna" ja perunat", olisivat lähellä toisiaan, koska ne eroavat vain yhdessä ulottuvuudessa. Lisäksi muutos olisi systemaattinen; sama vektori joka on sanojen "peruna" ja "perunat" välillä olisi sanojen "tietokone" ja tietokoneet" välillä.

Nykyään sanaupotuksia ei rakenneta tällä tavalla käsin, vaan ne kehitetään tilastollisesti laajan aineiston perusteella. Tässä esimerkissä käytetyt upotukset ovat neuroverkon "oppimia". Ne sijoittavat käyttötavaltaan samanlaiset sanat toistensa lähelle moniulotteisessa (esim. 100- tai 300-ulotteisessa) avaruudessa. Suuriulotteisuus tarkoittaa sitä, että käytössä on suuri määrä erilaisia "suuntia" joissa sanat voivat olla lähellä toisiaan ilman että väärät sanat päätyisivät toistensa lähelle (1- ulotteisessa avaruudessa, eli suoralla, sana voi olla toisen lähellä vain kahdessa suunnassa; vasemmalla tai oikealla).

Tässä esimerkissä sanaupotusten tärkein piirre on niiden välinen etäisyys, tässä tapauksessa ns. kosinietäisyys. Se vastaa sitä kulmaa, joka on kahden sanan paikkavektorien (origosta sanaan osoittava vektori) välillä. Eri ulottuvuudet ja suunnat ovat tämän etäisyyden kannalta samanarvoisia, mutta erilaisiin taivutusmuotoihin liittyvä vaihtelu on normalisoitu pois palauttamalla sanat perusmuotoihinsa ennen aineiston käyttöä upotusten luomiseen. Lisäksi käytämme etäisyyden sijaan samankaltaisuutta, joka saa arvon väliltä 0..2, missä 2 on maksimaalinen samankaltaisuus. Satunnaisten sanojen keskinäinen etäisyys on noin 1.

Esimerkiksi (pienemmästä) sanomalehtiaineistossa tehdyistä upotuksista voidaan tehdä sellainen havainto, että sanan "hiiri" 10 läheisimpään sanaan lukeutuu assosiaatioita viihdemaailmasta ("Mikki"), eläinmaailmasta ("apina", "rotta", "kissa", "hämähäkki", "sammakko") sekä elektroniikan maailmasta ("näppäimistö", "robotti", "kaukosäädin"). Tällaisenaan menetelmä siis sekoittaa merkityskentältään erilaiset mutta samannäköiset sanat, mitä voisi kutsua heikoksi homonymiaksi. Menetelmä on kuitenkin sikäli robusti, että kaikki löytyneet sanat perustellusti todella läheisesti liittyvät hakusanaan.

Tässä esimerkissä pääkiinnostuskohteemme on työttömyyden käsittely sanomalehdissä. Käyttämämme upotukset liittävät tähän hakusanaan

1. Yhdyssanoja, kuten nuorisotyöttömyys, pitkäaikaistyöttömyys ja työttömyysluku, sekä sanoja jotka liittyvät johdettuina työttömyyteen, kuten työtön
2. Talouteen liittyviä termejä, kuten valtionvelka, työvoimakustannus, inflaatio ja lama
3. Laajempia yhteiskunnallisia ilmiöitä, kuten muuttoliike, syntyvyys, väestökato ja köyhyys

Heti nähdään että sana "työttömyys" virittää melko laajan semanttisen kentän, joka kuitenkin selvästi voisi kertoa jotain kunkin aikakauden tilanteesta ja puheenaiheista.

Vertauksena neuroverkkoihin, tällaista kosinisamankaltaisuutta voidaan ajatella tiettyä aihepiiriä koskevan neuronin "aktivaationa". Artikkelille voidaan laskea "kokonaisaktivaatio" eri tavoin; tässä tapauksessa yksinkertainen ja tehokas valinta on koko artikkelin maksimiaktivaatio, eli valitaan artikkelia kuvaavaksi lukuarvoksi suurin samankaltaisuus, joka sanan "työttömyys" ja jokin artikkelin sana saa. (Neuroverkkomaailmassa tätä voisi ajatella yhden sanan konvoluutiona, jolle tehdään "max pooling" -normalisointi.)

## Prosessointi

Kun tavoitteeksi ollaan valittu edellämainittu maksimiaktivaatio, voidaan kunkin sanomalehtiarkistoon kuuluvan tekstin kokoa olennaisesti pienentää. Ensinnäkin, koska sanaupotuksissa on pelkkiä perusmuotoja, voidaan valita jokaisen sanomalehtitekstin sanan kohdalle sen perusmuoto (ja sivuuttaa kaikki muu tekstin mukana tuleva analyysi ja metadata paitsi julkaisupäivä). Seuraavaksi sanoista voidaan poistaa kaikki sellaiset joilla ei ole analyysin kannalta merkitystä, erityisesti hyvin yleiset, lähinnä kieliopilliset sanat ("stopwords"), lukusanat sekä välimerkit. Tässä vaiheessa voidaan myös havaita mikäli artikkeli ei vaikuta suomenkieliseltä ja sivuuttaa se. Seuraavaksi, koska sanojen järjestyksellä ja sillä, miten monta kertaa sana esiintyy, ei ole merkitystä, voidaan duplikaattisanat poistaa. Jos kaiken tämän jälkeen jäljellä on liian vähän sanoja, mikä johtuu yleensä digitoinnissa tapahtuneesta virheestä, artikkeli sivuutetaan.

Kaiken tämän seurauksena aineiston koko pienenee alle 5%:iin alkuperäisestä.

Kosinietäisyydet laskettiin tehokkaalla C++:lla toteutetulla kirjastolla jota käytettiin Python-ohjelmasta. Python-ohjelma laski jokaiselle vuodelle keskiarvot ja piirsi niistä kuvaajan.

Kansalliskirjaston aineisto on ajallisesti pahasti epätasainen. Vuosilta 1920-1944 aineistoa on gigatavuja vuosittain, vuosilta 1945-1975 satoja megatavuja, vuosilta 1976-1990 vain kymmeniä megatavuja, ja vuodesta 1991 eteenpäin ollaan jälleen gigatavuluokassa. Epätasaisuudet ovat niin suuria, pahimmillaan satakertaisia, että niiden aiheuttajana olevat metodologiset erot tekevät jaksoista keskenään huonosti vertailukelpoisia. Tämä näkyy seuraavassa kuvaajassa. y-akselissa näytetään kunkin vuoden artikkelien kosinisamankaltaisuuden keskiarvo, niin että kuvaajan alareunassa on arvo 0.4, jotta kuvaajassa näkyisi vuosien välinen vaihtelu selvemmin.

![Vuosien 1920-2000 sanomalehtiaineiston työttömyysindikaattori](https://github.com/Traubert/articles/blob/master/tyottomyys/työttömyys_1920_2000.png "Koko aineisto")

Kunnollista yhtenäistä, numeerista tilastotietoa työttömyydestä on vaikea löytää Internetistä. Jotain viitettä antaa kuitenkin [tällä sivulla](https://www.stat.fi/org/tilastokeskus/tyottomyysaste.html) oleva Tilastokeskuksen koostama kuvaaja vuosilta 1900-2015.

![Vuosien 1920-1944 sanomalehtiaineiston työttömyysindikaattori](https://github.com/Traubert/articles/blob/master/tyottomyys/työttömyys_1920_1944.png "1920-1944")

Kosinietäisyyskuvaajassa erottuu piikki vuosien 1930 ja 1935 välillä, ja tuona aikana kärsittiin myös suurtyöttömyydestä. Toisaalta kapeammat piikit on myös vuosien 1922 ja 1940 tienoilla. Kun tutkitaan tarkemmin, mitkä sanat saivat suurimman läheisyyden/aktivaation työttömyys-sanan kanssa, huomataan että 30-luvulla *työttömyys* nousee kärkikastiin, muina aikoina ei. 20-luvulla korostuvat sanat *palkka*, *yhteiskunta* ja *maatalous*. Suomi oli juuri käynyt sisällissodan, jonka osapuolten välinen erimielisyys yhteiskunnasta, tulonjaosta sekä maatalouden suuri merkitys senaikaisessa Suomessa mahdollisesti korostuvat. Sotavuonna 1940 näkynee osittain se, että sanomalehtiaineisto on tuolta vuodelta ollut tavallista vähäisempää, ja mahdollisesti asiapitoisuus korostuu keskiarvon laskemisessa. *Sairaus* ja *pelko* ovat tuolloin korkealla, ja tartuntataudit olivatkin merkittävä ongelma 1930-luvun lopulla ja 1940-luvulla. Huomionarvoista on sekin, että 30-luvulla *hinta* on yleisemmin kuin *palkka* läheisin löytynyt merkitys sanalle *työttömyys*, muina aikoina *palkka* on yleisempi kuin *hinta*.

![Vuosien 1945-1975 sanomalehtiaineiston työttömyysindikaattori](https://github.com/Traubert/articles/blob/master/tyottomyys/työttömyys_1945_1975.png "1945-1975")

Aikavälillä 1945-1975 ei ole niin merkittäviä piikkejä työttömyydessä kuin 1930-luvulla oli, mutta ainakin työttömyyden nousukaudet näyttäisivät jokseenkin osuvat yhteen kosinsamankaltaisuuspiikkien kanssa. Olisi mielenkiintoista tutkia, millainen tilastollinen yhteys on ensinnäkin tällä kuvaajalla ja työttömyydellä, ja toiseksikin tällä kuvaajalla ja työttömyyden kasvulla.

![Vuosien 1976-1990 sanomalehtiaineiston työttömyysindikaattori](https://github.com/Traubert/articles/blob/master/tyottomyys/työttömyys_1976_1990.png "1976-1990")

Tänä aikana korostuu aineiston vähäinen määrä ja sitä kautta heikko laatu. 1970-luvun lopun piikki ei näy mitenkään. Sanat *ongelma* ja *kriisi* korostuvat noina vuosina.

![Vuosien 1991-2000 sanomalehtiaineiston työttömyysindikaattori](https://github.com/Traubert/articles/blob/master/tyottomyys/työttömyys_1991_2000.png "1991-2000")

Nyt aineisto on laadukkaampaa, ja näyttää melko selvästi ensin pahenevan laman vaikutukset, sitten suotuisamman talouskehityksen. Sanat *työttömyys* ja *lama* korostuvat lamavuosina.
