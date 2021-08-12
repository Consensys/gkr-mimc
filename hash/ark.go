package hash

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// 100 random strings of x's and y's smaller than q
// generated in Python using
// str(random.randrange(21888242871839275222246405745257275088548364400416034343698204186575808495617))
// Naturally, they only works if we use ecc/bn254
var xArr []fr.Element
var yArr []fr.Element

// Arks contains the round constants used by gMimc
var Arks []fr.Element

func initArk() {

	xArr = make([]fr.Element, 100)
	yArr = make([]fr.Element, 100)
	Arks = make([]fr.Element, 100) // extra 0 at the beginning

	// Set the values of xArr
	for i, x := range [...]string{
		"20935598419934535773939197275086671883976426238465984892689893274776109706840",
		"19995897090389691161372090451896659673911988660285271218219666866949687188766",
		"6544978823936796530307517047600780472974960393678464677682762811474267306764",
		"13423806261013761719286154447241277236171190620841146940924235299828216919004",
		"483036459520899251433481070174077337588234874789277590744459238550542022336",
		"11834122008725238397540798432599519064159958632173342040922104816182977650323",
		"6214250652825909336042102302914495542350963467874575855196090802530598798684",
		"7170726223133665141339252286212434611716644939495742319100725465588758577975",
		"3628752144011358518780390633429771997829076043796856962918680101301334326717",
		"10995056073584958662633592981244351787463906518240783240839224906624462658946",
		"10316136354139206944774094995168509765583756998417835440724193449385724904064",
		"6887293571249137951954974829583961948681874052171040521689627599170432187821",
		"17679014255108003658018203734964304787939319117285088271374270937340979331088",
		"4248252868936221819819290432848672487864423222808359880150462211602494495796",
		"10838576758032918715215191218446338417881585877259434456182478933129676952115",
		"753652442023272502362984997608685353764283209436968416683175270126230919486",
		"17745848830945769523932902637022183346001315979559375020608322369317158742340",
		"15048113314350148976574068237122414221875489926515297088305374878755157475050",
		"9491283014185515531244157897882648088184249254485820722661277551261599129642",
		"4258129065487469195892729988726472140786148309087149042478972442852967621345",
		"5111992792738425366152826074931113105810075868173875109087887872181607527888",
		"17207570210536169229421619009051443126781777633310289161609677098462635375221",
		"11676857416455659283983679396450067066140186418683989409364053576635898614423",
		"17578181423085285483685548800623294414373345823336170149312376005897219810923",
		"16629480769556236124982722400255457396770056235490451205148220949109249575367",
		"8839117604736565297825617688776310968162145135592273200563883313600739705885",
		"1735306411626188875687496234040719696454614787672232638784102468564002525311",
		"1062690232563009764870609669688237582570790433844825729996364011137988522972",
		"10056158341775369056001372101480180671326250547841758558233836566253007463970",
		"12861676007242550257747460291682219623619046064334768768792486866981698984069",
		"10364293972625138632177507866607968975753973525749205969026186608034214999319",
		"3381310948007105111429534263163256529484284505313401397404454363021417678968",
		"5391644308855774040931138482213992529012013176810874072239316963239013418901",
		"5739902267984637424546093272789773631580642499147923310270611599926582772083",
		"20806058531191007742886071003337288700928126171889422302290828657325840002837",
		"1953912345352260990400998391590986884132317738887679700094700754944948270710",
		"6334107054196823364302483562051891503925658093315615419922191758990899370338",
		"14436872750302522612547342263479874128706597085400185002907467694318996568975",
		"7694649897497530249728485136604371802655316385667275552509740182346397459671",
		"19618789529866917206069877900825601316878403452146176103972243181682070108596",
		"2021370341346862593327202593746514936950566619994961739175029081766474759734",
		"8897565274181604271438529286082177443144026336582705290182549375856364873271",
		"2679449823911283247300632056535751191249091461631889726903592697866653888173",
		"20129895186588343211831804279732468237555926468631283725949859368323156032328",
		"13600013317168617656421359748934876309106612346394267276197743245554826828044",
		"4187390986581800164301365868618807900222521766711295721325192212473641955078",
		"17190735820869638808784313330525115090358120278752459902349090601764659379986",
		"7860693206750828547022882524196397915704308902872703437413899492234638169950",
		"263587684044448289719429684465217979694231526668589674423417665681979978672",
		"12954057757246385431776838652377320956920815107618502944864994612010557053917",
		"10625755329183920915841453005657772997523286066913835639471907499702448594328",
		"16175361036106772273053984695425631085622758695469708623031329115839090608091",
		"7924643236665918037726545377739468766171745922844271871159360253789090651662",
		"14745943428673947439440436509001772198518090233941952319627228181057581147947",
		"5200110725015095224900900401491425448872414730842690281649501292204903596258",
		"14844515653194611243517183917188743040195272988340890757893132638115648419361",
		"18284597462748499391597422334682707085291493485018550859047712392990049612585",
		"3312757768539360866544546712719153939543130555858880701206518185577866044127",
		"11494491995355104110478447591843802527037727080288399836711586597617930772246",
		"16270250187260095576918281103126175126400434232898666530090704942769826010320",
		"8680260951893149973525640389344225710096038075121190733144198459306153458739",
		"9081613210888370454812488310849186028647077567446266762039801934739912763318",
		"10956462511589282027775497802647259672358929202388777534828986598277518510940",
		"13370913492321313472348616113510256836815142270399966460977455242823363372922",
		"13435079246781743384843720328820403206129294071479578706749467351260674442286",
		"18388272646089823700512532610933652257193724639728928401647812388564816035072",
		"4824438688649902010762908031802598452324416083897401196317026545608670128170",
		"16639475199568140702564184960648997909998564302491101536025960422620186396737",
		"9698386349195157718988480221578364140594852561835995069755014032700861137184",
		"184730549537418551827887128923167602075009782174981658579083378380561403166",
		"5624105519689291645919891509613328425168570010590845601140173844081019857980",
		"7450716761741930677175278400352080652394237300409198906696001754049674530245",
		"5371470382394845195824877337361558168063810572261588627438109543648132090378",
		"15916615953942210085265747284146959402033948678792411724876166650637967413112",
		"17530212325321880583076096442221773546008840067636999101801153102182082050803",
		"3130575017506563486379643269706590265437956588003605259886854795479035081161",
		"21602532357228503237027076470426344915762613291631264074837835884431881157704",
		"18175480348381516617958634462144151473385342682669306435382223997224577647885",
		"11701690718026895346824771844850592436088535534550764165534456114515752003199",
		"12269837419960548249728971163700132941456486865685239188300851998035846614389",
		"2400291724637078032895220206931668428857913251539696626122517390770119598631",
		"3654343830276165868300300278633476909969601631321485759949471116592609195616",
		"17235144671932366808828254897445223424297026530200129204235663184234890499384",
		"20506680052641797427690296883223523332483431790083362449544093134410861331851",
		"17331504954904950505856350254389798927000070544870687548919051531188198807950",
		"6804161102614327828976510754243929743759943219061856517156987357363944829891",
		"2317479567028904415200602472561912467973945115634988693464542048750799278467",
		"18090469109511824152179049458653009408110373299245056594039366425863625295848",
		"10089848084586654625732745860585123183877862273820914158173224863878469115856",
		"1395836226546105948872057125025556411270566848892612832821620203563889793940",
		"10721598754291822821503791097285933118105954737347233142637972326192311886410",
		"8359345204686797469951453420353417935055941782617632382536541727457473046091",
		"11837750283757807457455756860464208427747288399432375587762853620364480448031",
		"15301971233817766320695731507409466149968450661632089583616278484482700364566",
		"6117002297131317426052982382004995803437168289348556329802949005764517586689",
		"8903395600979830544130884370204757215790326174543487725690925685601847291516",
		"13790842991390267676149228422665487445151021796150434526967048103377183722083",
		"9035559823192678393011406366902457990596065627959572306182158186900207605358",
		"8655223615688285377345725376026753443683911514166015415235267767049944934264",
		"17186780836005891388812353377183471046567173005401842455526923306475002070709"} {

		xArr[i].SetString(x)
	}

	for i, y := range [...]string{
		"7889220331855942390152844458153232881279298126168020718835532394961205897587",
		"4107703593865508008152532058450894262094481424817058071600894405707215391652",
		"2981965480119979542849598348825849434223710590643429757794916099804474854278",
		"6510902050797677829384445736759731040248069172634739272245379909319626488073",
		"8522870073131781488016212969787534099137132628889578006129058741893408941181",
		"11232025606036473857746482629338463504030960124294186766713483778447938231338",
		"21108530142895439895654172761661150753777692245579682285942822684968978554433",
		"10464664817782197858046869676929914985501473844890126267436644424377450552963",
		"9556974973279526871831633641120260160779911188908156358772760560288666751418",
		"1241372567008212377746166279809965298086156428510111101318502387802761219670",
		"16965808995810370462626517202842630591642545143655935980600413775621762532203",
		"14081836386157266284725623730380606274635205225974409983914017720589945843700",
		"15717493831146887482628108329054911883169147273489756037945534099976070774027",
		"18593090576191442420050903576531433518340171805085928714205763484336633105309",
		"1180731836490206389102149955923245281301919815522901801411607002856506167445",
		"5630609659278558017493034142969725450091515674276376879425166022960595487458",
		"21148350670392926881733606141800108701428090781255797670919919442016299030656",
		"15981546030195995367874935019352512874790725250109867282199269312633699915629",
		"7128052015328083284771085073609010750898929158617766974896019800003730550665",
		"6454471518821978428632182821258703281716542043625557058657747082108395391128",
		"18414607559334082314582901653915199096740838481712022680971572855497532846606",
		"4183726831064928874612108256656246798198704604512003866935655552220421419091",
		"507109504624490978450119158894577498030885167514463224819635968665207473223",
		"4808945797743944532330222116938040860765125452102486515966197626781851453765",
		"596504558625166257059093301467659831107500064953902351961806116733248199902",
		"1891458151530095404569000804740697696724660679385944694286672437478907510222",
		"12427768852750863462657510524722931983002850806185662441399170494087988656133",
		"12524602396618143105360965068865400589520832232935398577200379636653421496829",
		"10317176319397026634788809540621588848523541533718318733088702546661989262007",
		"1580596918288326863348722923866523000423264136344986653906336202047212027048",
		"6929143459167000241672166204183430630078568358548410719216285168231414683031",
		"10173256998300402553059050850081131439790068458053436588904913588514358470417",
		"9394145954207241148089853874036143168290380165365020395840910959745476073307",
		"13135390516961959054404413834161737161633928206137140011709268875521052233737",
		"12564350986146389941548491828894587312126483111975633109578712321107060383752",
		"1376491500521760150709492907973860555502715251541536838923266365618931406830",
		"8330775466866774738520407826351455126792841542039504412287605575890891747192",
		"8701576500767456261196164973750281031375892213475189335508532808123885067373",
		"16030142974555072707224309501362306430498788900149770180489521885630856377412",
		"17009220094833048875569562275612920502823608442311519823143885493886432964057",
		"13892080216395375698746931560259176937443429073833099032912514477312685821892",
		"16506694287892680248215076743413944982943234456066862229941320747945996007224",
		"2146811437233560927081428012168694503239422028313247606065184935643917198701",
		"3976229319282941213618566157961663797083392331239007102357688315789164689026",
		"16265853792125339173976869281862044762968348177681140751253978979029225522530",
		"14536954120167069032804365361277174806190017485542719968196592398476446880589",
		"18130529534729850307847740791671659268675809840961829951251618740400043870764",
		"14338057265451744973089233302821749361628076042233938369249313578334710172636",
		"19647231889458447797501252411484979149300154772839245739082606313523368528273",
		"20290678043421884446850792415593402100334966568961431979799398362492870969221",
		"7317436958444775238210672141424321168189998273907308555373508929036274633413",
		"9234435097223614475280721625079061129423171578705836489564699916616318385788",
		"5043619600308283288967791653456575033009808188361120667517975816759838969455",
		"14140513900676850412704402871686036764884759901882686270251696588209026919444",
		"2047328283108159420315021324644538293984254000489784806807390746008287238332",
		"5814411721062517079967797771653601251038338525707899051655286081361084310522",
		"6341197767327335307089281867928368166774239090958491991541758289006398667317",
		"9435915283405645088323234373771400328694005263909585840762615241219923218643",
		"13387243789278120572730908735093978599880866192723671043240558727701040341664",
		"14922064767941059898802635660418998171109153770248849019192832769461096614847",
		"5310923943943687463340194424403834984546129832719846198692245211825450770899",
		"851009140783773772512403908815075765128031465870408440630408820288915351355",
		"16697144460359443610930522567232593392051545681299784638301862128036778257566",
		"13669400607027362246135074818354681057821387163359271214689106684804762311417",
		"11141011258204312644640174523914553682780271756087434224860558481473358612359",
		"21043923187075097875733402828757809791382200839033414339963074884114432838476",
		"6774107457039269033319588169677712019543899952764388791605935463346806236879",
		"1431660334255478512185227973825287470142674265745864558177025018012516824381",
		"4695946731993663641084212622482542242369780629645938409682696955930468198734",
		"11288519124585374749333053504198144187726732736459576298847630122944821247265",
		"6627077352609406500088975387642304579089554332186025538151234828620879330636",
		"6482896472212179002872768082407898635388964565877980132395145112424810601918",
		"11001682864775142791446475972658780537632277347220793046046865329880263266846",
		"4277697710742254726581057339004435748034039969688558621456719243137568270875",
		"9481973311808249476289720795288455592483220972797058963968311255382356691809",
		"19971772865700811448218056122573347998664057348591672238129930017824012213547",
		"6110971391917572513629143113148458010047250352895271416327657609200332738295",
		"10208083437479749091663769290880341696951210333142239058982798491933369634658",
		"19371140597274853679292375926419652865869135313465054712996746675235918739169",
		"20971661560259707098854603768203949465180509867854450112616175986484870421138",
		"21838330569261441578087646010525345708120479655451726406087932484095187695549",
		"1076468390231167140360365402549282875608448404587397878869395031512647545868",
		"6092562878013814855183104955777715456621614617862565177117435129255704079816",
		"18170161495387533917334964667662143192347640390128446556717056467963418198054",
		"12109168190744162366750385102312029693950407650008338509019026459317895835309",
		"2544515291684966855280435972478516040217778310392748651232105437618227749994",
		"15507833383654996913475404388196490841449813254954018401673216235880494534754",
		"9380720655920370046211204946052206765055511343725830684785673543023741993312",
		"4075185557495157137658600992091098641694110615629352438267813211136993876650",
		"20717870862653987407155106996159787542440325578024314005823385621372755326674",
		"4815783172417066630729630018577795817279508567440163468943586637205331905419",
		"10191708984143774877397162783302180085783051650391418734913757161058566615716",
		"12709179554712235414695320020168637754351757243494418321394148981472365589549",
		"11713908815142029267977623070427886421590639997586227181669025742969514806643",
		"14975567209499876151412402594801810332666577737007342935060399369293114492453",
		"4297848205619735573379913160795364592161838502585648079402224506267602723902",
		"16395392222317019456016218924241407228380986050333722208118133679977446245065",
		"12959937773704006145335986634830507188953799862425156620262967430053968980597",
		"10611666550972266129080819432693421560818873779652376153152772165559569100498",
		"19720650681541961299836478555453123453649520285923438834236036850370957389533"} {

		yArr[i].SetString(y)
	}

	for i, a := range [...]string{
		"0", // artificially inserted for testing purposes (and in compliance with MiMC specification)
		"12136087830675299266258954793902014139747133950228959214677232437877732505267",
		"1949262915742616509924639087995052057439533688639443528419902050101511253219",
		"19696026105199390416727112585766461108620822978182620644600554326664686143928",
		"4837202928086718576193880638295431461498764555598430221157283092238776342056",
		"20604733757835564048563775050992717669420271708242272549953811572144277524421",
		"3211475718977376565880387313110606450525142591707961226303740825956563866938",
		"20322324153453907734144901224240556024026610989461831427966532469618423079473",
		"7934973319760976485021791030537501865656619719264759660277823446649082147312",
		"930415486950737914013769279801651475511858502656263669439342111832254726850",
		"13233069796564124818867608145207094060962111073577067140167532768756987412088",
		"21056848409984369169004352317081356901925342815742628419179104554944602838181",
		"7609965049060251551691128076452200168193674628022973404475256739231396295027",
		"2875569989607589080323784051637402876467307402338253586046146159474138388518",
		"1638405415371537336552461768985626566464351501714515162849864399640580102578",
		"15419971351110340210204119021937390512827818431981795058254849419538982779889",
		"6266520897908297023042570116888246900567139531590020770952602488348558265061",
		"14039893748423238973883972164169603996654684831868979824941451015257316714495",
		"17495914808944773938291362208338085117997720817217450529979495804567647637318",
		"5560043367941296663296908882927102318709803693167554571558317138775165457566",
		"679516368620232917376775416937269411660606739225677609931160531673791709159",
		"20771173458695616083113300195745636859853909352816078680615698162064064254487",
		"9061949945732349497554037671487309408019595175888253563639003740846345173268",
		"6589283089756049627166577132264171123481224689360969470370811604100156764233",
		"3533527516202756096389060356777395269308981839403476652028917646088724581131",
		"5616942227850617678046840250903304358333298306807220766347746809267032455299",
		"19134688161961603498559262912818080142324701420702686735061929518115443109100",
		"4455012138630075486254307533606858125267214265131501816598058811172692328101",
		"10793166202851599893237663367817743308639336679992856426902640679097285197834",
		"15056866545271068254544312503685146788561860865190761206515636207319868585312",
		"18588820303015761108497689698317977183405401884497470414262723108370171102023",
		"19833892328086915832797048699984794667331247199325415348986995942708708405059",
		"898953396730445825940003488465251983486876859688881180356386693085994272154",
		"11340240789075205057343229997968129213431697722131695573513514123825351727265",
		"19892667690111598338150747633561348627404155092311695371528902260306500224478",
		"5675265566752264879035374032667220698134217173464462106243551163373050847632",
		"20083467967117235977304805384179142748526655108920556941636271719496304583696",
		"17241462814856629393310447955833139605117065616411368427339901837278291194631",
		"459523005856707668283348902081873079675765291191967460823756003540662376503",
		"7536104111246397807428611027267470467060028762437526544651879177391629902952",
		"10590470262497492482063013216166955143786637478931633085736787678537413766247",
		"15043612058042949906959587136396856430320834576029342208816587940851697052752",
		"7330056066898340139347678689385900107077259949111182422329627141831221863855",
		"19916604609861621491722130626309103960340872015429661158412002662197451448107",
		"308306529997070213533139133875862443286398019572914380538015645187505823318",
		"16861578445042558674239888228729122953078668310622552358464602254565597746836",
		"2366359755939099031669574080770668941312280240662985815253933900628948645191",
		"8788914401574223424632781718358228468459844175515383031440552306265712071450",
		"9779987514099704007279027021166746630318148945176798063151889326895889174458",
		"13135609303826200140065220669831303027168227375851483214161433389386937614136",
		"11882415982617123710903704093174071260801610004108501667550482610326464450188",
		"4694986622157183973572682165500777613739137314689019399776788204304376634992",
		"2808898114262898635818480138517494241567797735868474755455378194917584076537",
		"5948815563212137849669729139804279433531777993372036737258762483412800936524",
		"8496838141077262636623013469780283761807018011829013896066741949043911303482",
		"13702702800086118773314822629146457886421384618509027653511022100403608735978",
		"128688574990165958444408798980207546660746573848805400153153989929390707086",
		"12715895361575110453437591483121803013655602937865783580504131050519779681504",
		"17179978120180957050330523849284167936336391317937861638141613431407020295629",
		"11588459002841336587102129061065070154347559648088906077759949716914737879289",
		"168729015953654988689927854892774175085256078299955360517770595983890795563",
		"17165830632129355357506266148952557268171444871293207481635264037052195045134",
		"12285138422811175780558426551904715989773712718224312428395575235466952713940",
		"1987154593247807270868347506717058470421782960151084491475247158475586184486",
		"936832494647391757736430222708683185711203089414475274201868885273866499292",
		"2763903754000480287708688930433393942277464250028040958350868219711066983212",
		"14557524245952597893636674984376061034140209715056307601099498105010811817976",
		"8621083546529398784671346534967410376642366851765751955141670352937262262964",
		"16627133697950876223520571090822797284529950315549243443213268507732589809668",
		"3037237623056839958281909328577143274349259163243900007898639886427035545715",
		"12995322444898226109150040488092296918287501169681313486450928080265859678431",
		"2733175139613460118331091475705229587335989342539982599327578628225987296693",
		"6330904024850799154241468252437391268363906860268077269679635105930910493698",
		"6737293883333053574354581827330797956286937344085463211929388455105153381840",
		"5169833748253678861646459610440007606812480863902145153341918680460199744937",
		"5663342152029876725337105797615457704649755088730278042317883168997297323658",
		"7823289338543622859281063471306327640697795333152031235270922571768144390442",
		"1340620010762718653929597746951102533345616951097596331852240652037854160258",
		"14897728869802140961598204911995631203157447569404601325674568226982309954150",
		"392018124866990209108785883333829486897323525593091953436038191276969589879",
		"435898044557960665437580260079284983588895103844486797156208731954139457048",
		"9993497896703025989867048646043173418345536355715949769299454237797386286833",
		"15450930933516186552123777405659014411420729103535031826405440554766901684012",
		"20903034268582375477673219601216374844076505392263195573819638253963628987677",
		"3482242022270674095230150345947605407241554167884470462727496514965587717020",
		"7327691729979824302166499451919150969294811677490604640371561147744223396077",
		"20320351461219902734279664936551332285309420491532838228883116430144043470224",
		"10080172065834582431913901068278960033644520993565022600527798146227389706243",
		"7585484857655643314874927439430217827126382955320388941459286281381839302612",
		"7020483570292313692729758704383267761829627767486597865215352770024378363713",
		"9412915321043344246413050595015332915226967771752410481732502466528909535915",
		"97172793343716602779526815707427204724123444268829991232994756079285191657",
		"9899367385098696963034612599611804167993369962788397262985493922791351318920",
		"20493102078330064462134068336666924427323601025383617983664121148357421387185",
		"3761041932368006457845986014429804620297172145142418054203286909040968118241",
		"1538739698002044525972417606140809601347518204915820728384854667109147333511",
		"13802243875617990810077229053159639403189861626210898918796014575383062790441",
		"14802416169101027248236235356384528498867388780049957297916199959694575989798",
		"12855744726651850023311564252614781422504814539761023618408723113057440886558",
		"3017365043038086323648780208528621420394032286007989775391627155784248978766",
		// "6315674106586331242761612192226077184856834393892197849679034296526217823177",
	} {

		Arks[i].SetString(a)
	}
}
