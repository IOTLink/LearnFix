/// 在运行此代码前，peer已经加载了环境变量，与core.yaml配置文件，好像也把证书文件加载进来了
```  
func serve(args []string) error {
    /// 账本初始化
	ledgermgmt.Initialize()
```

> 
> fabric->core->ledger->ledgermgmt->ledger_mgmt.go
> ``` 
> // Initialize initializes ledgermgmt
> func Initialize() {  
>   /// 保证只初始化一次
> 	once.Do(func() {
> 		initialize()
> 	})
> }
> 
> func initialize() {
> 	lock.Lock()
> 	defer lock.Unlock()  /// go automatic lock & unlock
>   /// 设置全局变量
> 	initialized = true
>   /// 将存放PeerLedger的全局变量openedLedgers初始化
> 	openedLedgers = make(map[string]ledger.PeerLedger)  /// this will be used in 'CreateLedger(genesisBlock *common.Block)'
>   /// 实例化了一个Provider
> 	provider, err := kvledger.NewProvider()
> ```
>> fabric->core->ledger->kvledger->kv_ledger_provider.go
>> ```
>> // NewProvider instantiates a new Provider.
>> // This is not thread-safe and assumed to be synchronized be the caller
>> func NewProvider() (ledger.PeerLedgerProvider, error) {
>> 
>> 	// Initialize the ID store (inventory of chainIds/ledgerIds)
>>  /// 获取文件路径
>> 	idStore := openIDStore(ledgerconfig.GetLedgerProviderPath())
>> 
>> 	// Initialize the block storage
>>  /// 一个字符串数组，里面有一些与block相关的字段
>> 	attrsToIndex := []blkstorage.IndexableAttr{
>> 		blkstorage.IndexableAttrBlockHash, /// BlockHash
>> 		blkstorage.IndexableAttrBlockNum, /// BlockNum
>> 		blkstorage.IndexableAttrTxID, /// TxID
>> 		blkstorage.IndexableAttrBlockNumTranNum, /// BlockNumTranNum
>> 		blkstorage.IndexableAttrBlockTxID, /// BlockTxID
>> 		blkstorage.IndexableAttrTxValidationCode, /// TxValidationCode
>> 	}
>>  /// 将那个字符串数组为一个全局变量赋值
>> 	indexConfig := &blkstorage.IndexConfig{AttrsToIndex: attrsToIndex}
>> 	blockStoreProvider := fsblkstorage.NewProvider(
>> 		fsblkstorage.NewConf(ledgerconfig.GetBlockStorePath(), ledgerconfig.GetMaxBlockfileSize()),
>> 		indexConfig)
>> 
>> 	// Initialize the versioned database (state database)
>>  /// 与配置数据库相关的信息，先看到这
>> 	var vdbProvider statedb.VersionedDBProvider
>> 	if !ledgerconfig.IsCouchDBEnabled() {
>> 		vdbProvider = stateleveldb.NewVersionedDBProvider()
>> 	} else {
>> 		var err error
>> 		vdbProvider, err = statecouchdb.NewVersionedDBProvider()
>> 	}
>> 
>> 	// Initialize the history database (index for history of values by key)
>> 	var historydbProvider historydb.HistoryDBProvider
>> 	historydbProvider = historyleveldb.NewHistoryDBProvider()
>> 
>> 	provider := &Provider{idStore, blockStoreProvider, vdbProvider, historydbProvider}
>> 	provider.recoverUnderConstructionLedger()
>> 	return provider, nil
>> }
>> ```
> ```
>   /// 将新创建的Provider赋值给全局变量
> 	ledgerProvider = provider
> }
> ```

```
	// Parameter overrides must be processed before any parameters are
	// cached. Failures to cache cause the server to terminate immediately.
	/// 设置chaincode配置参数，目前是写死的“dev”，以后应该有可选配置
	if chaincodeDevMode {  
		viper.Set("chaincode.mode", chaincode.DevModeUserRunsChaincode)
	}
    /// 配置，获取了Endpoint参数
	peerEndpoint, err := peer.GetPeerEndpoint()
```
> fabric->core->peer->config.go
> ```
> // GetPeerEndpoint returns peerEndpoint from cached configuration
> func GetPeerEndpoint() (*pb.PeerEndpoint, error) {
> ```
>>
>> ```
>> fabric->protos->peer->peer.pb.go
>> type PeerEndpoint struct {
>> 	Id      *PeerID `protobuf:"bytes,1,opt,name=id" json:"id,omitempty"`
>> 	Address string  `protobuf:"bytes,2,opt,name=address" json:"address,omitempty"`
>> }
>> ```
> ```
>   /// configurationCached 是一个全局bool型参数
> 	if !configurationCached {
>       /// 缓存配置参数
> 		cacheConfiguration()
> ```
>> fabric->core->peer->config.go
>> ```
>> // cacheConfiguration logs an error if error checks have failed.
>> func cacheConfiguration() {
>> 	if err := CacheConfiguration(); err != nil {
>> ```
>>> fabric->core->peer->config.go
>>> ```
>>> // Cached values of commonly used configuration constants.
>>> 
>>> // CacheConfiguration computes and caches commonly-used constants and
>>> // computed constants as package variables. Routines which were previously
>>> // global have been embedded here to preserve the original abstraction.
>>> func CacheConfiguration() (err error) {
>>> 
>>> 	// getLocalAddress returns the address:port the local peer is operating on.  Affected by env:peer.addressAutoDetect
>>> 	getLocalAddress := func() (peerAddress string, err error) {
>>> 		if viper.GetBool("peer.addressAutoDetect") {
>>> 			// Need to get the port from the peer.address setting, and append to the determined host IP
>>> 			_, port, err := net.SplitHostPort(viper.GetString("peer.address"))
>>> 			peerAddress = net.JoinHostPort(GetLocalIP(), port)
>>> 			peerLogger.Infof("Auto detected peer address: %s", peerAddress)
>>> 		} else {
>>> 			peerAddress = viper.GetString("peer.address")
>>> 		}
>>> 		return
>>> 	}
>>> 
>>> 	// getPeerEndpoint returns the PeerEndpoint for this Peer instance.  Affected by env:peer.addressAutoDetect
>>> 	getPeerEndpoint := func() (*pb.PeerEndpoint, error) {
>>> 		var peerAddress string
>>> 		peerAddress, err := getLocalAddress()
>>> 		return &pb.PeerEndpoint{Id: &pb.PeerID{Name: viper.GetString("peer.id")}, Address: peerAddress}, nil
>>> 	}
>>> 
>>> 	localAddress, localAddressError = getLocalAddress()
>>>     /// 配置参数中的peer.id：peer0.org1.example.com;Address:10.10.1.221:7051
>>> 	peerEndpoint, _ = getPeerEndpoint()
>>> 
>>> 	configurationCached = true
>>> 
>>> 	if localAddressError != nil {
>>> 		return localAddressError
>>> 	}
>>> 	return
>>> }
>>> ```
>> ```
>> 	}
>> }
>> ```
> ```
> 	}
> 	return peerEndpoint, peerEndpointError
> }
> ```
```
    /// 配置，获取监听地址：0.0.0.0:7051
	listenAddr := viper.GetString("peer.listenAddress")
    /// 获取安全相关的配置（证书一类的东西）
    /// 此语句是设置LTS相关证书
	secureConfig, err := peer.GetSecureConfig()
```
> fabric->core->peer->config.go
> ```
> // GetSecureConfig returns the secure server configuration for the peer
> /// 这个方法在配置‘CORE_PEER_TLS_ENABLED=false’之后，除了给secureConfig.UseTLS设置false，其他什么都没做
> func GetSecureConfig() (comm.SecureServerConfig, error) {
> 	secureConfig := comm.SecureServerConfig{
>       /// 是否使用TLS的配置参数
> 		UseTLS: viper.GetBool("peer.tls.enabled"),
> 	}
>   /// 如果参数设置为使用TLS
> 	if secureConfig.UseTLS {
> 		// get the certs from the file system
> 		serverKey, err := ioutil.ReadFile(config.GetPath("peer.tls.key.file"))
> 		serverCert, err := ioutil.ReadFile(config.GetPath("peer.tls.cert.file"))
> 		// must have both key and cert file
> 		if err != nil {
> 			return secureConfig, fmt.Errorf("Error loading TLS key and/or certificate (%s)", err)
> 		}
> 		secureConfig.ServerCertificate = serverCert
> 		secureConfig.ServerKey = serverKey
> 		// check for root cert
> 		if config.GetPath("peer.tls.rootcert.file") != "" {
> 			rootCert, err := ioutil.ReadFile(config.GetPath("peer.tls.rootcert.file"))
> 			if err != nil {
> 				return secureConfig, fmt.Errorf("Error loading TLS root certificate (%s)", err)
> 			}
> 			secureConfig.ServerRootCAs = [][]byte{rootCert}
> 		}
> 		return secureConfig, nil
> 	}
>   /// 如果不使用
> 	return secureConfig, nil
> }
> ```
```
    /// 创建了一个PeerServer
	peerServer, err := peer.CreatePeerServer(listenAddr, secureConfig)
```
> fabric->core->peer->peer.go
> ```
> // CreatePeerServer creates an instance of comm.GRPCServer
> // This server is used for peer communications
> func CreatePeerServer(listenAddress string,
> 	secureConfig comm.SecureServerConfig) (comm.GRPCServer, error) {
> 
> 	var err error
> 	peerServer, err = comm.NewGRPCServer(listenAddress, secureConfig)
> ```
>> fabric->core->comm->server.go
>> ```
>> //NewGRPCServer creates a new implementation of a GRPCServer given a
>> //listen address.
>> func NewGRPCServer(address string, secureConfig SecureServerConfig) (GRPCServer, error) {
>> 
>> 	if address == "" {
>> 		return nil, errors.New("Missing address parameter")
>> 	}
>> 	//create our listener
>> 	lis, err := net.Listen("tcp", address)
>> 
>> 	return NewGRPCServerFromListener(lis, secureConfig)
>> ```
>>> fabric->core->comm->server.go
>>> ```
>>> //NewGRPCServerFromListener creates a new implementation of a GRPCServer given
>>> //an existing net.Listener instance.
>>> func NewGRPCServerFromListener(listener net.Listener, secureConfig SecureServerConfig) (GRPCServer, error) {
>>>     // 定义了一个grpcServer实现
>>> 	grpcServer := &grpcServerImpl{
>>> 		address:  listener.Addr().String(),
>>> 		listener: listener,
>>> 		lock:     &sync.Mutex{},
>>> 	}
>>> 
>>> 	//set up our server options
>>> 	var serverOpts []grpc.ServerOption
>>> 	//check secureConfig
>>>     /// 目前没用TLS，以下代码块没运行
>>> 	if secureConfig.UseTLS {
>>> 		//both key and cert are required
>>> 		if secureConfig.ServerKey != nil && secureConfig.ServerCertificate != nil {
>>> 			grpcServer.tlsEnabled = true
>>> 			//load server public and private keys
>>> 			cert, err := tls.X509KeyPair(secureConfig.ServerCertificate, secureConfig.ServerKey)
>>> 			if err != nil {
>>> 				return nil, err
>>> 			}
>>> 			grpcServer.serverCertificate = cert
>>> 
>>> 			//set up our TLS config
>>> 
>>> 			//base server certificate
>>> 			certificates := []tls.Certificate{grpcServer.serverCertificate}
>>> 			grpcServer.tlsConfig = &tls.Config{
>>> 				Certificates:           certificates,
>>> 				SessionTicketsDisabled: true,
>>> 			}
>>> 			grpcServer.tlsConfig.ClientAuth = tls.RequestClientCert
>>> 			//checkif client authentication is required
>>> 			if secureConfig.RequireClientCert {
>>> 				//require TLS client auth
>>> 				grpcServer.tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
>>> 				//if we have client root CAs, create a certPool
>>> 				if len(secureConfig.ClientRootCAs) > 0 {
>>> 					grpcServer.clientRootCAs = make(map[string]*x509.Certificate)
>>> 					grpcServer.tlsConfig.ClientCAs = x509.NewCertPool()
>>> 					for _, clientRootCA := range secureConfig.ClientRootCAs {
>>> 						err = grpcServer.appendClientRootCA(clientRootCA)
>>> 						if err != nil {
>>> 							return nil, err
>>> 						}
>>> 					}
>>> 				}
>>> 			}
>>> 
>>> 			// create credentials and add to server options
>>> 			creds := NewServerTransportCredentials(grpcServer.tlsConfig)
>>> 			serverOpts = append(serverOpts, grpc.Creds(creds))
>>> 		} else {
>>> 			return nil, errors.New("secureConfig must contain both ServerKey and " +
>>> 				"ServerCertificate when UseTLS is true")
>>> 		}
>>> 	}
>>>     /// TLS相关结束
>>> 	// set max send and recv msg sizes
>>>     /// 向数组添加最大发送消息的方法
>>> 	serverOpts = append(serverOpts, grpc.MaxSendMsgSize(MaxSendMsgSize()))
>>>     /// 向数组添加了最大接收消息的方法
>>> 	serverOpts = append(serverOpts, grpc.MaxRecvMsgSize(MaxRecvMsgSize()))
>>> 	// set the keepalive options
>>>     /// 设置超时时间
>>> 	serverOpts = append(serverOpts, ServerKeepaliveOptions()...)
>>>     /// 向定义的grpcServer结构体里添加了一个基础的GRPCServer。
>>> 	grpcServer.server = grpc.NewServer(serverOpts...)
>>> 
>>> 	return grpcServer, nil
>>> }
>>> ```
>> ```
>> }
>> ```
> ```   
>   /// peerServer是对一个基础的GrpcServer指定Address,Listener的封装
> 	return peerServer, nil
> }
> ```
```
    /// LTS配置相关，目前没用到
	if secureConfig.UseTLS {
		// set up CA support
		caSupport := comm.GetCASupport()
		caSupport.ServerRootCAs = secureConfig.ServerRootCAs
	}
	//TODO - do we need different SSL material for events ?
	/// 创建一个EventHubServer,这个server是监听事件的吧
	ehubGrpcServer, err := createEventHubServer(secureConfig)
```
> fabric->peer->node->start.go
> ```
>  func createEventHubServer(secureConfig comm.SecureServerConfig) (comm.GRPCServer, error) {
> 	var lis net.Listener
>   /// tcp模式监听了一个地址
> 	lis, err = net.Listen("tcp", viper.GetString("peer.events.address"))
>   /// 创建了一个GrpcServer
> 	grpcServer, err := comm.NewGRPCServerFromListener(lis, secureConfig)
>   /// 创建了一个eventServer,但是这个Server不是那种GrpcServer。好像只是获取线程中传来的参数
> 	ehServer := producer.NewEventsServer(
> 		uint(viper.GetInt("peer.events.buffersize")),
> 		viper.GetDuration("peer.events.timeout"))
>   /// 注册到grpcServer,这应该是将grpcServer与ehServer进行关联；也就是将ehServer放在grpcServer的结构体里，然后形成了一个service
> 	pb.RegisterEventsServer(grpcServer.Server(), ehServer)
> ```
>> fabric->protos->peer->events.pb.go
>> ```
>> func RegisterEventsServer(s *grpc.Server, srv EventsServer) {
>> 	s.RegisterService(&_Events_serviceDesc, srv)
>> ```
>>> fabric->vendor->google.golang.org->grpc->server.go
>>> ```
>>> // RegisterService registers a service and its implementation to the gRPC
>>> // server. It is called from the IDL generated code. This must be called before
>>> // invoking Serve.
>>> func (s *Server) RegisterService(sd *ServiceDesc, ss interface{}) {
>>> 	/// 取了sd.HandlerType的类型，由于sd.HandlerType有两个类型所以用了Elem()，这个Elem()
>>> 	/// 我不知道reflect会返回什么
>>> 	ht := reflect.TypeOf(sd.HandlerType).Elem()
>>> 	st := reflect.TypeOf(ss)
>>> 	if !st.Implements(ht) {
>>> 		/// 这是个log封装
>>> 		grpclog.Fatalf("grpc: Server.RegisterService found the handler of type %v that does not satisfy %v", st, ht)
>>> 	}
>>> 	s.register(sd, ss)
>>> ```
>>>> fabric->vendor->google.golang.org->grpc->server.go
>>>> ```
>>>> func (s *Server) register(sd *ServiceDesc, ss interface{}) {
>>>> 	s.mu.Lock()
>>>> 	defer s.mu.Unlock()
>>>> 	s.printf("RegisterService(%q)", sd.ServiceName)
>>>> 	if _, ok := s.m[sd.ServiceName]; ok {
>>>> 		grpclog.Fatalf("grpc: Server.RegisterService found duplicate service registration for %q", sd.ServiceName)
>>>> 	}
>>>> 	srv := &service{
>>>> 		server: ss,
>>>> 		md:     make(map[string]*MethodDesc),
>>>> 		sd:     make(map[string]*StreamDesc),
>>>> 		mdata:  sd.Metadata,
>>>> 	}
>>>> 	for i := range sd.Methods {
>>>> 		d := &sd.Methods[i]
>>>> 		srv.md[d.MethodName] = d
>>>> 	}
>>>> 	for i := range sd.Streams {
>>>> 		d := &sd.Streams[i]
>>>> 		srv.sd[d.StreamName] = d
>>>> 	}
>>>> 	s.m[sd.ServiceName] = srv
>>>> }
>>>> ```
>>> ```
>>> }
>>> ```
>> ```
>> }
>> ```
> ```
> 	return grpcServer, nil
> }
> ```
```
	// enable the cache of chaincode info
	/// 开启ChainCode信息缓存 算是ChainCode配置吧 设置了fabric->core->common->ccprovide->ccprovider.go中的ccInfoCacheEnabled为true
	ccprovider.EnableCCInfoCache()
    /// 使用peerServer和监听地址，创建chaincode Server；
	ccSrv, ccEpFunc := createChaincodeServer(peerServer, listenAddr)
``` 
> fabric->peer->node->start.go 
> ```
> //create a CC listener using peer.chaincodeListenAddress (and if that's not set use peer.peerAddress)
> /// 当指定了"peer.chaincodeListenAddress"且不与peerListenAddress相同时，会得到一个新的GRPCServer，否则就用传入的PeerServer
> /// 但是目前配置文件注释掉了这个参数，所以先按PeerServer算
> func createChaincodeServer(peerServer comm.GRPCServer, peerListenAddress string) (comm.GRPCServer, ccEndpointFunc) {
> 	/// 配置参数，获取了peer的chaincode监听地址，但是在core.yaml中，这个默认被注释掉了
> 	cclistenAddress := viper.GetString("peer.chaincodeListenAddress")
> 	var srv comm.GRPCServer
> 	var ccEpFunc ccEndpointFunc
> 	//use the chaincode address endpoint function..
> 	//three cases
> 	// -  peer.chaincodeListenAddress not specied (use peer's server)
> 	// -  peer.chaincodeListenAddress identical to peer.listenAddress (use peer's server)
> 	// -  peer.chaincodeListenAddress different and specified (create chaincode server)
> 	/// 由于之前没有拿到cclistenAddress，所以使用了peer.GetPeerEndpoint的地址作为ccEndPoint地址
> 	if cclistenAddress == "" {
> 		//we are using peer address, use peer endpoint
> 		ccEpFunc = peer.GetPeerEndpoint
> 		srv = peerServer
> 	} else if cclistenAddress == peerListenAddress {
> 		//we are using peer address, use peer endpoint
> 		ccEpFunc = peer.GetPeerEndpoint
> 		srv = peerServer
> 	} else {
> 		config, err := peer.GetSecureConfig()
> 
> 		srv, err = comm.NewGRPCServer(cclistenAddress, config)
> 		ccEpFunc = getChaincodeAddressEndpoint
> 	}
> 
> 	return srv, ccEpFunc
> }
> 
> ```
```
	/// 利用ChainCodeServer注册了一个ChainCode支持
	/// ccSrv.Server()是在 peer.CreatePeerServer(listenAddr, secureConfig)时创建的一个grpcServer
	registerChaincodeSupport(ccSrv.Server(), ccEpFunc)
```
> fabric->peer->node->start.go
> ``` 
> //NOTE - when we implment JOIN we will no longer pass the chainID as param
> //The chaincode support will come up without registering system chaincodes
> //which will be registered only during join phase.
> func registerChaincodeSupport(grpcServer *grpc.Server, ccEpFunc ccEndpointFunc) {
> 	//get user mode
> 	/// 判断是不是dev模式，目前是而且只有这个模式，目前userRunsCC为true
> 	userRunsCC := chaincode.IsDevMode()
> 
> 	//get chaincode startup timeout
> 	/// 超时处理，目前不看
> 	ccStartupTimeout := viper.GetDuration("chaincode.startuptimeout")
> 	if ccStartupTimeout < time.Duration(5)*time.Second {
> 		logger.Warningf("Invalid chaincode startup timeout value %s (should be at least 5s); defaulting to 5s", ccStartupTimeout)
> 		ccStartupTimeout = time.Duration(5) * time.Second
> 	} else {
> 		logger.Debugf("Chaincode startup timeout value set to %s", ccStartupTimeout)
> 	}
> 	/// 创建了一个新的chaincode Support实例
> 	ccSrv := chaincode.NewChaincodeSupport(ccEpFunc, userRunsCC, ccStartupTimeout)
> 
> 	//Now that chaincode is initialized, register all system chaincodes.
> 	/// 这是注册了所有的system chaincode，这个system chaincode是写死在代码里的
> 	scc.RegisterSysCCs()
> 	/// 往 ccSrv.Server() 里又注册了一个chaincode Server,这个可能是server套server,还是换了一个server?
> 	pb.RegisterChaincodeSupportServer(grpcServer, ccSrv)
> ```
>> fabric->protos->peer->chaincode_shim.pb.go
>> ```
>> func RegisterChaincodeSupportServer(s *grpc.Server, srv ChaincodeSupportServer) {
>> 	/// &_ChaincodeSupport_serviceDesc 这个是干什么的，现在真是不知道,感觉是要给这个server注册一个proto对象，但是，为什么要注册这种东西?也可能这个是一个proto服务
>> 	s.RegisterService(&_ChaincodeSupport_serviceDesc, srv)
>> ```
>>> fabric->protos->peer->chaincode_shim.pb.go
>>> ```
>>> var _ChaincodeSupport_serviceDesc = grpc.ServiceDesc{
>>> 	ServiceName: "protos.ChaincodeSupport",
>>> 	HandlerType: (*ChaincodeSupportServer)(nil),
>>> 	Methods:     []grpc.MethodDesc{},
>>> 	Streams: []grpc.StreamDesc{
>>> 		{
>>> 			StreamName:    "Register",
>>> 			Handler:       _ChaincodeSupport_Register_Handler,
>>> 			ServerStreams: true,
>>> 			ClientStreams: true,
>>> 		},
>>> 	},
>>> 	Metadata: "peer/chaincode_shim.proto",
>>> }
>>> ```
>> ```
>> }
>> ```
> ```
> }
> ``` 
``` 
	/// 开启ChainCodeServer
	/* 1.创建PeerServer;2.创建EventHubServer;3.创建ChainCodeServer;4.注册ChainCodeSupport;5.启动ChainCodeServer */
	/// 启动了这个chaincode Support服务，具体怎么start,得看google.golang.org/grpc的库
	go ccSrv.Start()
	// Register the Admin server
	/// 利用PeerServer注册AdminServer;PeerServer应该与AdminServer有某种关联
	pb.RegisterAdminServer(peerServer.Server(), core.NewAdminServer())
```
> fabric->protos->peer->admin.pb.go
> ```
> func RegisterAdminServer(s *grpc.Server, srv AdminServer) {
> 	// 这个也是注册了一个proto相关的东西，现在看来grpc server这个东西一窍不通的话不行	
> 	s.RegisterService(&_Admin_serviceDesc, srv)
> }
> ```
```
	// Register the Endorser server
	/// 新建一个背书人的服务
	serverEndorser := endorser.NewEndorserServer()
```
> fabric->core->endorser->endorser.go
> ```
> // NewEndorserServer creates and returns a new Endorser server instance.
> func NewEndorserServer() pb.EndorserServer {
> 	e := new(Endorser)
> 	e.policyChecker = policy.NewPolicyChecker(
> 		/// 获得了一大堆接口，干什么用的？
> 		peer.NewChannelPolicyManagerGetter(),
> 		/// 这两个也是获得了一大堆接口。干什么用的？
> 		mgmt.GetLocalMSP(),
> 		mgmt.NewLocalMSPPrincipalGetter(),
> 	)
> 	return e
> }
> ```
```
	// AdminServer注册新建的背书人Server;这几步这些东西是怎么关联的，得好好查看查看
	pb.RegisterEndorserServer(peerServer.Server(), serverEndorser)
```
> fabric->protos->peer->peer.pb.go
> 好像太多地方用到这个protos包了
> ```
> func RegisterEndorserServer(s *grpc.Server, srv EndorserServer) {
> 	s.RegisterService(&_Endorser_serviceDesc, srv)
> }
> ```
```
	// Initialize gossip component
	/// 获取全局参数，core.yaml中 “127.0.0.1:7051”
	bootstrap := viper.GetStringSlice("peer.gossip.bootstrap")
    /// 获取本地签名身份
	serializedIdentity, err := mgmt.GetLocalSigningIdentityOrPanic().Serialize()
```
> fabric->msp->mgmt->mgmt.go
> ```
> // GetLocalSigningIdentityOrPanic returns the local signing identity or panic in case
> // or error
> /// 获取本地的签名实体
> func GetLocalSigningIdentityOrPanic() msp.SigningIdentity {
> 	id, err := GetLocalMSP().GetDefaultSigningIdentity()
> ```
>> fabric->msp->mgmt->mgmt.go
>> ```
>> // GetLocalMSP returns the local msp (and creates it if it doesn't exist)
>> func GetLocalMSP() msp.MSP {
>> 	var lclMsp msp.MSP
>> 	var created bool = false
>> 	{
>> 		m.Lock()
>> 		defer m.Unlock()
>> 		/// 经过DEBUG，在第一次执行peer node start的时候“localMsp”为nil，其他情况时未经测试。
>> 		lclMsp = localMsp 
>> 		if lclMsp == nil { 
>> 			/// 标志位
>> 			created = true
>> 			/// 获得了一个空的“bccspmsp”实体
>> 			lclMsp, err = msp.NewBccspMsp()
>> 			/// 设置为localMsp也能引用这个实体，那么其他时候获取localMsp的时候便不为nil了
>> 			localMsp = lclMsp
>> 		}
>> 	}
>> 	return lclMsp
>> }
>> ```
>> fabric->msp->mspimpl.go
>> ```
>> // GetDefaultSigningIdentity returns the
>> // default signing identity for this MSP (if any)
>> func (msp *bccspmsp) GetDefaultSigningIdentity() (SigningIdentity, error) {
>> 	mspLogger.Debugf("Obtaining default signing identity")
>> 	/// 这个"msp.signer"代码注释里说的是一列签名的实体，但目前不知道到底是什么样的实体
>>  /// 这个一点一点的能跟出来，不过目前脑力有点跟不上，下午再说
>> 	return msp.signer, nil
>> }
>> ```
> ```
> 	return id
> }
> ```
```
    /// 创建了一个mspMessageCryptoService的实例；应该是用于Peer的组织间通讯？
	messageCryptoService := peergossip.NewMCS(
		peer.NewChannelPolicyManagerGetter(),
		localmsp.NewSigner(),
		mgmt.NewDeserializersManager())
``` 
> fabric->peer->gossip->mcs.go
> ```
> // NewMCS creates a new instance of mspMessageCryptoService
> // that implements MessageCryptoService.
> // The method takes in input:
> // 1. a policies.ChannelPolicyManagerGetter that gives access to the policy manager of a given channel via the Manager method.
> // 2. an instance of crypto.LocalSigner
> // 3. an identity deserializer manager
> func NewMCS(channelPolicyManagerGetter policies.ChannelPolicyManagerGetter, localSigner crypto.LocalSigner, deserializer mgmt.DeserializersManager) api.MessageCryptoService {
> ```
>> fabric->core-peer->peer.go
>> ```
>> // NewChannelPolicyManagerGetter returns a new instance of ChannelPolicyManagerGetter
>> /// 返回了一个新实例，但实例是空的，估计是调用方法时会有用吧
>> func NewChannelPolicyManagerGetter() policies.ChannelPolicyManagerGetter {
>> 	return &channelPolicyManagerGetter{}
>> }
>> type channelPolicyManagerGetter struct{}
>> ```
>> fabric->common->localmsp->signer.go
>> ```
>> // NewSigner returns a new instance of the msp-based LocalSigner.
>> // It assumes that the local msp has been already initialized.
>> // Look at mspmgmt.LoadLocalMsp for further information.
>> /// 获取了空结构体实例
>> func NewSigner() crypto.LocalSigner {
>> 	return &mspSigner{}
>> }
>> type mspSigner struct {}
>> ```
>> fabric->msp->mgmt->deserializer.go
>> ```
>> // DeserializersManager returns a new instance of DeserializersManager
>> /// 又获取了一个空的结构体实例
>> func NewDeserializersManager() DeserializersManager {
>> 	return &mspDeserializersManager{}
>> }
>> type mspDeserializersManager struct{}
>> ```
> ```
> 	/// 获取了一个包含三个结构体的结构体，这个结构体注释里说是“mspMessageCryptoService”接口的实现
> 	return &mspMessageCryptoService{channelPolicyManagerGetter: channelPolicyManagerGetter, localSigner: localSigner, deserializer: deserializer}
> ```
>> fabric->peer->gossip->msc.go
>> ```
>> // mspMessageCryptoService implements the MessageCryptoService interface
>> // using the peer MSPs (local and channel-related)
>> //
>> // In order for the system to be secure it is vital to have the
>> // MSPs to be up-to-date. Channels' MSPs are updated via
>> // configuration transactions distributed by the ordering service.
>> //
>> // A similar mechanism needs to be in place to update the local MSP, as well.
>> // This implementation assumes that these mechanisms are all in place and working.
>> type mspMessageCryptoService struct {
>> 	channelPolicyManagerGetter policies.ChannelPolicyManagerGetter
>> 	localSigner                crypto.LocalSigner
>> 	deserializer               mgmt.DeserializersManager
>> }
>> ```
> ```
> }
> ```
``` 
	/// 创建了一个mspSecurityAdvisor
	secAdv := peergossip.NewSecurityAdvisor(mgmt.NewDeserializersManager())
```
> fabric->msp->mgmt->deserializer.go
> ```
> // DeserializersManager returns a new instance of DeserializersManager
> // 我是不是应该看看这种实例化空结构体方法的空结构体的能耐
> func NewDeserializersManager() DeserializersManager {
> 	return &mspDeserializersManager{}
> }
> 
> type mspDeserializersManager struct{}
> ```
> fabric->peer->gossip->sa.go
> ```
> // NewSecurityAdvisor creates a new instance of mspSecurityAdvisor
> // that implements MessageCryptoService
> func NewSecurityAdvisor(deserializer mgmt.DeserializersManager) api.SecurityAdvisor {
> 	return &mspSecurityAdvisor{deserializer: deserializer}
> }
> // mspSecurityAdvisor implements the SecurityAdvisor interface
> // using peer's MSPs.
> //
> // In order for the system to be secure it is vital to have the
> // MSPs to be up-to-date. Channels' MSPs are updated via
> // configuration transactions distributed by the ordering service.
> //
> // This implementation assumes that these mechanisms are all in place and working.
> /// 感觉 就是往自身不断的储存对象，每个对象里面所包含的功能稍后补上
> type mspSecurityAdvisor struct {
> 	deserializer mgmt.DeserializersManager
> }
> ```
```
	// callback function for secure dial options for gossip service
	/// 闭包，作用是得到了一个设置选项的数组，设置了消息大小，和保持活动时间
	secureDialOpts := func() []grpc.DialOption {
		var dialOpts []grpc.DialOption
		// set max send/recv msg sizes
		/// 设置了最大发送/接收消息大小
		dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(comm.MaxRecvMsgSize()),
			grpc.MaxCallSendMsgSize(comm.MaxSendMsgSize())))
		// set the keepalive options
		dialOpts = append(dialOpts, comm.ClientKeepaliveOptions()...)
		/// 此处为false,目前不开启TLS
		if comm.TLSEnabled() {
			tlsCert := peerServer.ServerCertificate()
			dialOpts = append(dialOpts, grpc.WithTransportCredentials(comm.GetCASupport().GetPeerCredentials(tlsCert)))
		} else {
			dialOpts = append(dialOpts, grpc.WithInsecure())
		}
		return dialOpts
	}
	/// 初始化GossipService
	err = service.InitGossipService(serializedIdentity, peerEndpoint.Address, peerServer.Server(),
		messageCryptoService, secAdv, secureDialOpts, bootstrap...)
```
> fabric->gossip->service->gossip_service.go
> ```
> // InitGossipService initialize gossip service
> func InitGossipService(peerIdentity []byte, endpoint string, s *grpc.Server, mcs api.MessageCryptoService,
> 	secAdv api.SecurityAdvisor, secureDialOpts api.PeerSecureDialOpts, bootPeers ...string) error {
> 	// TODO: Remove this.
> 	// TODO: This is a temporary work-around to make the gossip leader election module load its logger at startup
> 	// TODO: in order for the flogging package to register this logger in time so it can set the log levels as requested in the config
> 	/// 应该是log相关
> 	util.GetLogger(util.LoggingElectionModule, "")
> 	return InitGossipServiceCustomDeliveryFactory(peerIdentity, endpoint, s, &deliveryFactoryImpl{}, mcs, secAdv, secureDialOpts, bootPeers...)
> ```
>> fabric->gossip->service->gossip_service.go
>> ```
>> // InitGossipServiceCustomDeliveryFactory initialize gossip service with customize delivery factory
>> // implementation, might be useful for testing and mocking purposes
>> func InitGossipServiceCustomDeliveryFactory(peerIdentity []byte, endpoint string, s *grpc.Server,
>> 	factory DeliveryServiceFactory, mcs api.MessageCryptoService, secAdv api.SecurityAdvisor,
>> 	secureDialOpts api.PeerSecureDialOpts, bootPeers ...string) error {
>> 	var err error
>> 	var gossip gossip.Gossip
>> 	once.Do(func() {
>> 		if overrideEndpoint := viper.GetString("peer.gossip.endpoint"); overrideEndpoint != "" {
>> 			endpoint = overrideEndpoint
>> 		}
>> 
>> 		idMapper := identity.NewIdentityMapper(mcs, peerIdentity)
>> 		gossip, err = integration.NewGossipComponent(peerIdentity, endpoint, s, secAdv, mcs, idMapper, secureDialOpts, bootPeers...)
>> 		/// 返回了一个实例化的"gossipService"结构体
>> 		gossipServiceInstance = &gossipServiceImpl{
>> 			mcs:             mcs,
>> 			gossipSvc:       gossip,
>> 			chains:          make(map[string]state.GossipStateProvider),
>> 			leaderElection:  make(map[string]election.LeaderElectionService),
>> 			deliveryFactory: factory,
>> 			idMapper:        idMapper,
>> 			peerIdentity:    peerIdentity,
>> 			secAdv:          secAdv,
>> 		}
>> 	})
>> 	return err
>> }
>> ```
> ```
> }
> ```
```
    /// 在代码块运行完之后关闭GossipService
	defer service.GetGossipService().Stop()

	//initialize system chaincodes
	/// 启动ChainCode
	initSysCCs()
```
> fabric->peer->node->start.go
> ```
> //start chaincodes
> /// 部署系统自带的chaincode
> func initSysCCs() {
> 	//deploy system chaincodes
> 	scc.DeploySysCCs("")
> ```
>> fabric->core->scc->importsysccs.go
>> ```
>> //DeploySysCCs is the hook for system chaincodes where system chaincodes are registered with the fabric
>> //note the chaincode must still be deployed and launched like a user chaincode will be
>> func DeploySysCCs(chainID string) {
>> 	for _, sysCC := range systemChaincodes {
>> 		deploySysCC(chainID, sysCC)
>> ```
>>> fabric->core->scc->sysccapi.go
>>> ```
>>> // deploySysCC deploys the given system chaincode on a chain
>>> /// 部署系统chaincode
>>> func deploySysCC(chainID string, syscc *SystemChaincode) error {
>>> 	
>>> 	ccprov := ccprovider.GetChaincodeProvider()
>>> ```
>>>> fabric->core->common->ccprovider->ccprovider.go
>>>> ```
>>>> // GetChaincodeProvider returns instances of ChaincodeProvider;
>>>> // the actual implementation is controlled by the factory that
>>>> // is registered via RegisterChaincodeProviderFactory
>>>> func GetChaincodeProvider() ChaincodeProvider {
>>>> 	/// 返回了一个新建chaincodeProvider的接口
>>>> 	return ccFactory.NewChaincodeProvider()
>>>> }
>>>> ```
>>> ```
>>> 	/// 不知道这个是干啥的
>>> 	ctxt := context.Background()
>>> 	if chainID != "" {
>>> 		/// 这个应该是获得了一个账本，但是由于chainID没有给出，所以应该是得到了一个nil
>>> 		lgr := peer.GetLedger(chainID)
>>> 		_, err := ccprov.GetContext(lgr)
>>> 		defer ccprov.ReleaseContext()
>>> 	}
>>> 
>>> 	chaincodeID := &pb.ChaincodeID{Path: syscc.Path, Name: syscc.Name}
>>> 	spec := &pb.ChaincodeSpec{Type: pb.ChaincodeSpec_Type(pb.ChaincodeSpec_Type_value["GOLANG"]), ChaincodeId: chaincodeID, Input: &pb.ChaincodeInput{Args: syscc.InitArgs}}
>>> 
>>> 	// First build and get the deployment spec
>>> 	chaincodeDeploymentSpec, err := buildSysCC(ctxt, spec)
>>> 
>>> 	txid := util.GenerateUUID()
>>> 
>>> 	version := util.GetSysCCVersion()
>>> 
>>> 	cccid := ccprov.GetCCContext(chainID, chaincodeDeploymentSpec.ChaincodeSpec.ChaincodeId.Name, version, txid, true, nil, nil)
>>> 
>>> 	_, _, err = ccprov.ExecuteWithErrorFilter(ctxt, cccid, chaincodeDeploymentSpec)
>>> 
>>> 	return err
>>> }
>>> ```
>> ```
>> 	}
>> }
>> /// 系统里自带chaincode
>> //see systemchaincode_test.go for an example using "sample_syscc"
>> var systemChaincodes = []*SystemChaincode{
>> 	{
>> 		Enabled:           true,
>> 		Name:              "cscc",
>> 		Path:              "github.com/hyperledger/fabric/core/scc/cscc",
>> 		InitArgs:          [][]byte{[]byte("")},
>> 		Chaincode:         &cscc.PeerConfiger{},
>> 		InvokableExternal: true, // cscc is invoked to join a channel
>> 	},
>> 	{
>> 		Enabled:           true,
>> 		Name:              "lscc",
>> 		Path:              "github.com/hyperledger/fabric/core/scc/lscc",
>> 		InitArgs:          [][]byte{[]byte("")},
>> 		Chaincode:         &lscc.LifeCycleSysCC{},
>> 		InvokableExternal: true, // lscc is invoked to deploy new chaincodes
>> 		InvokableCC2CC:    true, // lscc can be invoked by other chaincodes
>> 	},
>> 	{
>> 		Enabled:   true,
>> 		Name:      "escc",
>> 		Path:      "github.com/hyperledger/fabric/core/scc/escc",
>> 		InitArgs:  [][]byte{[]byte("")},
>> 		Chaincode: &escc.EndorserOneValidSignature{},
>> 	},
>> 	{
>> 		Enabled:   true,
>> 		Name:      "vscc",
>> 		Path:      "github.com/hyperledger/fabric/core/scc/vscc",
>> 		InitArgs:  [][]byte{[]byte("")},
>> 		Chaincode: &vscc.ValidatorOneValidSignature{},
>> 	},
>> 	{
>> 		Enabled:           true,
>> 		Name:              "qscc",
>> 		Path:              "github.com/hyperledger/fabric/core/chaincode/qscc",
>> 		InitArgs:          [][]byte{[]byte("")},
>> 		Chaincode:         &qscc.LedgerQuerier{},
>> 		InvokableExternal: true, // qscc can be invoked to retrieve blocks
>> 		InvokableCC2CC:    true, // qscc can be invoked to retrieve blocks also by a cc
>> 	},
>> }
>> ```
> ```
> }
> ```
```
	//this brings up all the chains (including testchainid)
	/// Peer初始化
	peer.Initialize(func(cid string) {
	    /// 部署了系统的ChainCode
		scc.DeploySysCCs(cid)
	})

	// Start the grpc server. Done in a goroutine so we can deploy the
	// genesis block if needed.
	/// 创建了一个Error通道的空间,
	serve := make(chan error)
    /// 创建了系统信号通道的空间
	sigs := make(chan os.Signal, 1)
	/// 
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		serve <- nil
	}()

	go func() {
		var grpcErr error
		if grpcErr = peerServer.Start(); grpcErr != nil {
			grpcErr = fmt.Errorf("grpc server exited with error: %s", grpcErr)
		} else {
		}
		serve <- grpcErr
	}()
    /// 将Pid写入文件，“peer.fileSystemPath”在core.yaml中定义
	if err := writePid(config.GetPath("peer.fileSystemPath")+"/peer.pid", os.Getpid()); err != nil {
		return err
	}

	// Start the event hub server
	if ehubGrpcServer != nil {
	    /// 启动EventHubServer
		go ehubGrpcServer.Start()
	}

	// Start profiling http endpoint if enabled
	/// 参数配置相关
	if viper.GetBool("peer.profile.enabled") {
		go func() {
			profileListenAddress := viper.GetString("peer.profile.listenAddress")
			/// 启动一个监听，配置文件默认为0.0.0.0:6060
			if profileErr := http.ListenAndServe(profileListenAddress, nil); profileErr != nil {
			}
		}()
	}

	// set the logging level for specific modules defined via environment
	// variables or core.yaml
	overrideLogModules := []string{"msp", "gossip", "ledger", "cauthdsl", "policies", "grpc"}
	for _, module := range overrideLogModules {
	    /// 与Log相关的东西，目前不重要
		err = common.SetLogLevelFromViper(module)
		if err != nil {
		}
	}
    /// 
	flogging.SetPeerStartupModulesMap()
	// Block until grpc server exits
	return <-serve
}

```