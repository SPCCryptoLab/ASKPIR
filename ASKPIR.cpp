#include "../mpc/pso/mqrpmt_psi.hpp"
#include "../crypto/setup.hpp"
#include "../crypto/ec_point.hpp"
#include "../crypto/ec_group.hpp"
#include "../commitment/pedersen.hpp"
#include <cstdlib>
#include <string>
#include <openssl/sha.h>
#include <iostream>  
using namespace std;
struct TestCase{
    size_t LOG_SENDER_LEN; 
    size_t LOG_RECEIVER_LEN; 
    size_t SENDER_LEN; 
    size_t RECEIVER_LEN; 
    std::vector<block> vec_X; // sender's set
    std::vector<block> vec_Y; // receiver's set
    std::vector<block> vec_D; // user's value
    size_t HAMMING_WEIGHT; // cardinality of intersection
    std::vector<uint8_t> vec_indication_bit; // X[i] = Y[i] iff b[i] = 1 

    std::vector<block> vec_intersection; // for PSI 

};

// LEN is the cardinality of two sets
TestCase GenTestCase(size_t LOG_SENDER_LEN, size_t LOG_RECEIVER_LEN)
{
    TestCase testcase;

    testcase.LOG_SENDER_LEN = LOG_SENDER_LEN; 
    testcase.LOG_RECEIVER_LEN = LOG_RECEIVER_LEN; 
    testcase.SENDER_LEN = size_t(pow(2, testcase.LOG_SENDER_LEN));  
    testcase.RECEIVER_LEN = size_t(pow(2, testcase.LOG_RECEIVER_LEN)); 

    PRG::Seed seed = PRG::SetSeed(nullptr, 0); // initialize PRG
    testcase.vec_X = PRG::GenRandomBlocks(seed, testcase.SENDER_LEN);
    testcase.vec_Y = PRG::GenRandomBlocks(seed, testcase.RECEIVER_LEN);
    testcase.vec_D = PRG::GenRandomBlocks(seed, testcase.SENDER_LEN);

    // set the Hamming weight to be a half of the max possible intersection size
    testcase.HAMMING_WEIGHT = std::min(testcase.SENDER_LEN, testcase.RECEIVER_LEN)/2;

    // generate a random indication bit vector conditioned on given Hamming weight
    testcase.vec_indication_bit.resize(testcase.SENDER_LEN);  
    for(auto i = 0; i < testcase.SENDER_LEN; i++){
        if(i < testcase.HAMMING_WEIGHT) testcase.vec_indication_bit[i] = 1; 
        else testcase.vec_indication_bit[i] = 0; 
    }
    std::shuffle(testcase.vec_indication_bit.begin(), testcase.vec_indication_bit.end(), global_built_in_prg);

    // adjust vec_X and vec_Y
    for(auto i = 0, j = 0; i < testcase.SENDER_LEN; i++){
        if(testcase.vec_indication_bit[i] == 1){
            testcase.vec_X[i] = testcase.vec_Y[j];
            testcase.vec_intersection.emplace_back(testcase.vec_Y[j]); 
            j++; 
        }
    }

    std::shuffle(testcase.vec_Y.begin(), testcase.vec_Y.end(), global_built_in_prg);

    return testcase; 
}

void PrintTestCase(TestCase testcase)
{
    PrintSplitLine('-'); 
    std::cout << "TESTCASE INFO >>>" << std::endl;
    std::cout << "Sender's set size = " << testcase.SENDER_LEN << std::endl;
    std::cout << "Receiver's set size = " << testcase.RECEIVER_LEN << std::endl;
    std::cout << "Intersection cardinality = " << testcase.HAMMING_WEIGHT << std::endl; 
    PrintSplitLine('-'); 
}

void SaveTestCase(TestCase &testcase, std::string testcase_filename)
{
    std::ofstream fout; 
    fout.open(testcase_filename, std::ios::binary); 
    if(!fout)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }

    fout << testcase.LOG_SENDER_LEN; 
    fout << testcase.LOG_RECEIVER_LEN; 
    fout << testcase.SENDER_LEN; 
    fout << testcase.RECEIVER_LEN; 
    fout << testcase.HAMMING_WEIGHT; 
     
    fout << testcase.vec_X; 
    fout << testcase.vec_Y; 
    fout << testcase.vec_D; 
    fout << testcase.vec_indication_bit;
    fout << testcase.vec_intersection; 

    fout.close(); 
}

void FetchTestCase(TestCase &testcase, std::string testcase_filename)
{
    std::ifstream fin; 
    fin.open(testcase_filename, std::ios::binary); 
    if(!fin)
    {
        std::cerr << testcase_filename << " open error" << std::endl;
        exit(1); 
    }

    fin >> testcase.LOG_SENDER_LEN; 
    fin >> testcase.LOG_RECEIVER_LEN; 
    fin >> testcase.SENDER_LEN; 
    fin >> testcase.RECEIVER_LEN;
    fin >> testcase.HAMMING_WEIGHT; 

    testcase.vec_X.resize(testcase.SENDER_LEN); 
    testcase.vec_Y.resize(testcase.RECEIVER_LEN); 
    testcase.vec_D.resize(testcase.SENDER_LEN); 
    testcase.vec_indication_bit.resize(testcase.SENDER_LEN); 
    testcase.vec_intersection.resize(testcase.HAMMING_WEIGHT);   

    fin >> testcase.vec_X; 
    fin >> testcase.vec_Y; 
    fin >> testcase.vec_D; 
    fin >> testcase.vec_indication_bit;
    fin >> testcase.vec_intersection; 

    fin.close(); 
}

/*void string_multiply(string num1, uint8_t num2) {
        size_t n1 = num1.size(), n2 = num2.size();
        uint8_t ans(n1 + n2, '0');
        
        for(auto  i = n1 - 1; i >= 0; i--) {
        	for(int j = n2 - 1; j >= 0; j--) {
        		int temp = (ans[i + j + 1] - '0') + (num1[i] - '0') * (num2[j] - '0');
        		ans[i + j + 1] = temp % 10 + '0';
        		ans[i + j] += temp / 10;
        	}
        }
        
        for(int i = 0; i < n1 + n2; i++) {
        	if (ans[i] != '0') return ans.substr(i);
        }
        
    
     }*/
     string stringAdd(string num1,string num2){
        int i = num1.size()-1,j = num2.size()-1,add = 0;
        string ans = "";
        while(i >= 0 || j >= 0 || add != 0){
            int x = i >= 0 ? num1[i] - '0' : 0;
            int y = j >= 0 ? num2[j] - '0' : 0;//转数字
            int sum = x + y + add;//按位相加
            ans.push_back(sum % 10 + '0');//+‘0’转string
            add = sum / 10;//进位
            j--;
            i--;
        }
        reverse(ans.begin(),ans.end()); 
        return ans;
    }

     string multiply(string num1, uint8_t* num22) {
        //string num1( (char *) num11);
        string num2( (char *) num22);
        if(num1 == "0" || num2 == "0"){
            return "0";
        }
        string ans = "";
        int n1 = num1.size(), n2 = num2.size();
        for(int i = n2 -1; i >= 0; i--){//遍历num2的每一位，分别与num1的每一位相乘
            string cur;//保存num2中的一位和num1相乘的结果
            int add = 0;//进位
            for(int j = n2-1; j > i; j--){
                cur.push_back('0');//除了最低位以外，其余的每一位的运算结果都需要补0,
            }
            for(int k = n1 - 1; k >= 0; k--){//挨个相乘
                int product = (num1[k] - '0') * (num2[i] - '0') + add;//转数字相乘
                cur.push_back(product % 10 + '0');//转string再push进cur
                add = product / 10;//进位
            }
            if(add != 0){
                cur.push_back(add  + '0');
                //add = add / 10;
            }
            reverse(cur.begin(), cur.end());
            ans = stringAdd(ans, cur);//把num2中的每一位和num1相乘的结果（cur），加起来
        }
    
        return ans;    
    }

string string_to_hex(const string& str) //transfer string to hex-string
{
    string result="0x";
    string tmp;
    stringstream ss;
    for(int i=0;i<str.size();i++)
    {
        ss<<hex<<int(str[i])<<endl;
        ss>>tmp;
        result+=tmp;
    }
    return result;
}

struct PP
{
    ECPoint g; 
    std::vector<ECPoint> vec_h;  
    size_t N_max; 
};

PP Setup (size_t N_max)
{ 
    PP pp;
    pp.N_max = N_max;
    pp.g = ECPoint(generator); 
    /* 
    ** warning: the following method is ad-hoc and insafe cause it is not transparent
    ** we left a secure hash to many points mapping as the future work   
    */
    pp.vec_h = GenRandomECPointVector(N_max); 
    return pp; 
}
string GetBinaryStringFromHexString (string strHex)
{
    string sReturn = "";
    unsigned int len = strHex.length();
    for (unsigned int i = 0; i<len; i++)
    {
        switch ( strHex[i])
        {
            case '0': sReturn.append ("0000"); break;
            case '1': sReturn.append ("0001"); break;
            case '2': sReturn.append ("0010"); break;
            case '3': sReturn.append ("0011"); break;
            case '4': sReturn.append ("0100"); break;
            case '5': sReturn.append ("0101"); break;
            case '6': sReturn.append ("0110"); break;
            case '7': sReturn.append ("0111"); break;
            case '8': sReturn.append ("1000"); break;
            case '9': sReturn.append ("1001"); break;
            case 'A': sReturn.append ("1010"); break;
            case 'B': sReturn.append ("1011"); break;
            case 'C': sReturn.append ("1100"); break;
            case 'D': sReturn.append ("1101"); break;
            case 'E': sReturn.append ("1110"); break;
            case 'F': sReturn.append ("1111"); break;
        }
    }
    return sReturn;
}


ECPoint Commit(PP &pp,  std::vector<BigInt>& vec_m, BigInt r)
{
    if(pp.N_max < vec_m.size()){
        std::cerr << "message size is less than pp size" << std::endl;
    }
    size_t LEN = vec_m.size();
    std::vector<ECPoint> subvec_h(pp.vec_h.begin(), pp.vec_h.begin() + LEN);
    ECPoint commitment = pp.g * r + ECPointVectorMul(subvec_h, vec_m);
    return commitment;   
}

std::string sha256(const std::string& str) {
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    md = EVP_sha256();
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    EVP_DigestUpdate(mdctx, str.c_str(), str.length());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    char hex[2 * md_len + 1];
    for (unsigned int i = 0; i < md_len; ++i) {
        sprintf(&hex[i * 2], "%02x", md_value[i]);
    }

    return std::string(hex, 2 * md_len);
}

int main()
{
    CRYPTO_Initialize(); 
   // ECPoint G = ECPoint(generator); 
    //ECPoint H = GenRandomECPoint(); 
    //std::cout<<G.CompareTo(H)<<std::endl;
    





    std::cout << "mqRPMT-based PSI test begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "mqRPMTPSI.pp"; 
    mqRPMTPSI::PP pp;   
    if(!FileExist(pp_filename)){
        std::cout << pp_filename << " does not exist" << std::endl; 
        std::string filter_type = "bloom"; 
        size_t computational_security_parameter = 128;         
        size_t statistical_security_parameter = 40; 
        size_t LOG_SENDER_LEN = 20;
        size_t LOG_RECEIVER_LEN = 12;  
        pp = mqRPMTPSI::Setup("bloom", computational_security_parameter, statistical_security_parameter, 
                              LOG_SENDER_LEN, LOG_RECEIVER_LEN); 
        mqRPMTPSI::SavePP(pp, pp_filename); 
    }
    else{
        std::cout << pp_filename << " already exists" << std::endl; 
        mqRPMTPSI::FetchPP(pp, pp_filename); 
    }

    std::string testcase_filename = "mqRPMTPSI.testcase"; 
    
    // generate test instance (must be same for server and client)
    TestCase testcase; 
    if(!FileExist(testcase_filename)){ 
        std::cout << testcase_filename << " does not exist" << std::endl; 
        testcase = GenTestCase(pp.LOG_SENDER_LEN, pp.LOG_RECEIVER_LEN); 
        SaveTestCase(testcase, testcase_filename); 
    }
    else{
        std::cout << testcase_filename << " already exist" << std::endl; 
        FetchTestCase(testcase, testcase_filename);
        if((testcase.LOG_SENDER_LEN != pp.LOG_SENDER_LEN) || (testcase.LOG_SENDER_LEN != pp.LOG_SENDER_LEN)){
            std::cerr << "testcase and public parameter do not match" << std::endl; 
        }
    }
  auto start_time = std::chrono::steady_clock::now(); 
// sk Generate
size_t DID_sk_len = testcase.vec_Y.size(); 
 std::vector<int> DID_sk(DID_sk_len);
 for (auto i = 0; i < testcase.RECEIVER_LEN; i++) {
        
        DID_sk[i]= rand(); 

    }
 
    std::vector<uint8_t> HID_randnum;
    size_t testcase_HID_LEN = testcase.vec_Y.size(); 
    std::vector<std::vector<uint8_t>> vec_HID(testcase_HID_LEN,std::vector<uint8_t>(testcase_HID_LEN));
    vector<string> vec_UID(testcase_HID_LEN);
    vector<string> vec_UID_hex(testcase_HID_LEN);
    vector<string> vec_UID_bit(testcase_HID_LEN);
    string vec_UID_bit_num="";
    //UID Generate
    for (auto i = 0; i < testcase.RECEIVER_LEN; i++) {
          //std::cout<<"vec_HID[i].data()"<<std::endl;
          BasicHash((uint8_t*)(testcase.vec_Y.data()+i),sizeof(block), vec_HID[i].data());
          //std::cout<<"11111111"<<std::endl;
          //std::cout<<"vec_HID[i].data()"<<vec_HID[i].data()<<std::endl;
          int HID_random=rand();
          //HID_randnum[i]=rand(); 
          //std::cout<<"HID_randnum[i]"<<ii<<std::endl;
          //string d = multiply( HID_randnum[i],vec_HID[i].data());
          //uint8_t* char_array[d.length()];
          vec_UID[i]=multiply(std::to_string(HID_random),vec_HID[i].data());
          vec_UID_hex[i]=string_to_hex(vec_UID[i]);
          //std::cout<<"UID"<<multiply( HID_randnum[i],vec_HID[i].data())<<std::endl;
           //std::cout<<"UID"<<vec_UID_hex[i]<<std::endl;
          //break;
          vec_UID_bit[i]=GetBinaryStringFromHexString(vec_UID_hex[i]);
          vec_UID_bit_num=vec_UID_bit_num+vec_UID_bit[i];
    }
           //std::cout<<"ec_UID_bit_num"<<vec_UID_bit_num<<std::endl;
   
     string did="did:";
     string protocol="ASKPIR:";
     size_t N_max = testcase.RECEIVER_LEN; 
     PP com_pp = Setup(N_max); 
     std::vector<BigInt> BN_UID(testcase.RECEIVER_LEN);
     std::vector<BigInt> BN_sk(testcase.RECEIVER_LEN);
     std::vector<ECPoint> Pederson_commitment(testcase.RECEIVER_LEN);
     std::vector<string> Pederson_commitment_str(testcase.RECEIVER_LEN);
     std::vector<string> Pederson_commitment_hex(testcase_HID_LEN);
     std::vector<string> DID(testcase_HID_LEN);
     BigInt k_1=GenRandomBigIntLessThan(order); 
     std::vector<ECPoint> W (testcase.RECEIVER_LEN);
     std::vector<ECPoint> u (testcase.RECEIVER_LEN);
     std::vector<string> u_str(testcase.RECEIVER_LEN);
     std::vector<string> u_hex(testcase_HID_LEN);
    vector<string> DID_bit(testcase_HID_LEN);
    string DID_double_num="";
    vector<string> u_bit(testcase_HID_LEN);
    string u_double_num="";
     //DID u Generate
     for (auto i = 0; i < testcase.RECEIVER_LEN; i++) {
         BN_sk[i]=Hash::StringToBigInt(std::to_string(DID_sk[i]));
         BN_UID[i]=Hash::StringToBigInt(vec_UID[i]);
         Pederson_commitment[i] = Commit(com_pp,BN_sk,BN_sk[i]);
         Pederson_commitment_str[i]="";
         Pederson_commitment_str[i]+=Pederson_commitment[i].ToByteString();
         Pederson_commitment_hex[i]=string_to_hex(Pederson_commitment_str[i]);
         DID[i]=did+protocol+Pederson_commitment_hex[i];
        // std::cout<<"DID[i]"<<DID[i]<<std::endl;

         W[i]=com_pp.g*k_1;
         u[i]=W[i]*BN_UID[i];
         u_str[i]="";
         u_str[i]+=u[i].ToByteString();
         u_hex[i]=string_to_hex(u_str[i]);
        // std::cout<<"u[i]"<<u_hex[i]<<std::endl;
         //break;
        DID_bit[i]=GetBinaryStringFromHexString(DID[i]);
        DID_double_num=DID_double_num+DID_bit[i];

        u_bit[i]=GetBinaryStringFromHexString(u_hex[i]);
        u_double_num=u_double_num+u_bit[i];




    } 
    //std::cout<<"ec_UID_bit_num"<<DID_double_num<<std::endl;
    //std::cout<<"ec_UID_bit_num"<<u_double_num<<std::endl;

    
    //GenProof
     std::vector<BigInt> r_1(testcase.RECEIVER_LEN);
     std::vector<BigInt> r_2(testcase.RECEIVER_LEN);
     //std::vector<BigInt> length_1(testcase.SENDER_LEN+100);
     std::vector<BigInt> length(testcase.RECEIVER_LEN);
     std::vector<ECPoint> Q_1 (testcase.RECEIVER_LEN);
     std::vector<ECPoint> Q_2 (testcase.RECEIVER_LEN);
     std::vector<string> Q_1_str (testcase.RECEIVER_LEN);
     std::vector<string> Q_2_str (testcase.RECEIVER_LEN);
     std::vector<string> Q_3_str (testcase.RECEIVER_LEN);
     std::vector<BigInt> s_1(testcase.RECEIVER_LEN);
     std::vector<BigInt> s_2(testcase.SENDER_LEN);
     std::vector<BigInt> BN_c_1(testcase.RECEIVER_LEN);
     std::vector<string> s_1_str(testcase.RECEIVER_LEN);
     std::vector<string> s_2_str(testcase.RECEIVER_LEN);
     std::vector<string> BN_c_1_str(testcase.RECEIVER_LEN);
    std::vector<string> result1(testcase.RECEIVER_LEN);
     std::vector<string> result2(testcase.RECEIVER_LEN);
      //std::vector<string> str_c_1(testcase.SENDER_LEN+100);
    // size_t testcase_HID_LEN = testcase.vec_X.size(); 
     std::vector<std::vector<uint8_t>> vec_c_1(testcase_HID_LEN,std::vector<uint8_t>(testcase_HID_LEN));
    //std::vector<std::vector<string>> vec_c_1_str(testcase_HID_LEN,std::vector<string>(testcase_HID_LEN));
   // string vec_c_1_str[testcase.SENDER_LEN+100];
  
    vector<string> c_bit(testcase_HID_LEN);
   string c_double_num="";
    vector<string> s_1_bit(testcase_HID_LEN);
   string s_1_double_num="";
    vector<string> s_2_bit(testcase_HID_LEN);
    string s_2_double_num="";
   // std::vector<string> result1(testcase.RECEIVER_LEN+100);
    for (auto i = 0; i < testcase.RECEIVER_LEN; i++) {
         r_1[i]=GenRandomBigIntLessThan(order); 
         r_2[i]=GenRandomBigIntLessThan(order); 
         Q_1[i]=com_pp.g*r_1[i]+com_pp.vec_h[i]*r_2[i];
        //std::cout<<"Hash::ECPointToString(Q_1[i])"<<Hash::ECPointToString(Q_1[i])<<std::endl;

        
         Q_2[i]=W[i]*r_1[i];
        //std::cout<<"Hash::ECPointToString(Q_2[i])"<<Hash::ECPointToString(Q_2[i])<<std::endl;
         
         Q_1_str[i]+=Hash::ECPointToString(Q_1[i]);
         //std::cout<<"Q_1_str[i]"<<Q_1_str[i]<<std::endl;
         Q_2_str[i]+=Hash::ECPointToString(Q_2[i]);
        // std::cout<<"Q_2_str[i]"<<Q_2_str[i]<<std::endl;
         Q_3_str[i]=Q_1_str[i]+Q_2_str[i];

         length[i]=Q_3_str[i].length();

         //length_2[i]=Q_2_str[i].length();
      //  std::cout<<"Q_3_str[i]"<<Q_3_str[i]<<std::endl;
       // BasicHash((uint8_t*)((Q_3_str.data())+i),sizeof(length[i]), vec_c_1[i].data());
           result1[i]= sha256(Q_3_str[i]);
         //std::cout<<"vec_c_1[i].data()"<<vec_c_1[i].data()<<std::endl;
       // std::cout<<"vec_c_1[i].data()"<<vec_c_1[i].data()<<std::endl;
         // string vec_c_1_str="";
          string vec_c_1_str( (char*) vec_c_1[i].data());
          BN_c_1[i]=Hash::StringToBigInt(vec_c_1_str);
          //std::cout<<"vec_c_1_str"<<vec_c_1_str<<std::endl;
          s_1[i]=r_1[i]-BN_UID[i]*BN_c_1[i];
          s_2[i]=r_2[i]-BN_sk[i]*BN_c_1[i];
          s_1_str[i]=s_1[i].ToHexString();
          // std::cout<<"s_1_str[i]"<<s_1_str[i]<<std::endl;
          s_2_str[i]=s_2[i].ToHexString();
          //std::cout<<"s_2_str[i]"<<s_2_str[i]<<std::endl;
          BN_c_1_str[i]=BN_c_1[i].ToHexString();
           // std::cout<<"BN_c_1_str[i]"<<BN_c_1_str[i]<<std::endl;
         //vec_c_1_str=""; 
        
    
        c_bit[i]=GetBinaryStringFromHexString(BN_c_1_str[i]);
        c_double_num=c_double_num+c_bit[i];

        s_1_bit[i]=GetBinaryStringFromHexString(s_1_str[i]);
        s_1_double_num=s_1_double_num+s_1_bit[i];

        s_2_bit[i]=GetBinaryStringFromHexString(s_2_str[i]);
        s_2_double_num=s_2_double_num+s_2_bit[i];
        

    }  
    auto end_time_1 = std::chrono::steady_clock::now(); 
    auto running_time_1 = end_time_1 - start_time;
    std::cout << "Gen Authorization takes time = " 
              << std::chrono::duration <double, std::milli> (running_time_1).count() << " ms" << std::endl;
    //std::cout<<"s_1_double_num"<<c_double_num.size()<<std::endl;
   // std::cout<<"s_2_double_num"<<s_2_double_num<<std::endl;
     std::cout << "Communication Cost of Authorization" << " [" 
              << (c_double_num.size()+s_1_double_num.size()+s_2_double_num.size()+DID_double_num.size()+u_double_num.size()+vec_UID_bit_num.size())<< " MB]" << std::endl;  

   std::cout << "Communication Cost of Authorization" << " [" 
              << (c_double_num.size()+s_1_double_num.size()+s_2_double_num.size()+DID_double_num.size()+u_double_num.size()+vec_UID_bit_num.size())/(1024*1024)<< " MB]" << std::endl; 
//VerfProof
    std::vector<bool> vec_condition(testcase.RECEIVER_LEN, true);
     //std::vector<BigInt> length_1(testcase.SENDER_LEN+100);
     std::vector<BigInt> length_1(testcase.RECEIVER_LEN);
     std::vector<ECPoint> Q_4 (testcase.RECEIVER_LEN);
     std::vector<ECPoint> Q_5 (testcase.RECEIVER_LEN);
     std::vector<string> Q_4_str (testcase.RECEIVER_LEN);
     std::vector<string> Q_5_str (testcase.RECEIVER_LEN);
     std::vector<string> Q_6_str (testcase.RECEIVER_LEN);
     std::vector<BigInt> BN_c_2(testcase.RECEIVER_LEN);
     std::vector<string> BN_c_2_str(testcase.RECEIVER_LEN);
     //std::vector<string> result2(testcase.RECEIVER_LEN+100);
      //std::vector<string> str_c_1(testcase.SENDER_LEN+100);
    // size_t testcase_HID_LEN = testcase.vec_X.size(); 
     std::vector<std::vector<uint8_t>> vec_c_2(testcase_HID_LEN,std::vector<uint8_t>(testcase_HID_LEN));
    //std::vector<std::vector<string>> vec_c_1_str(testcase_HID_LEN,std::vector<string>(testcase_HID_LEN));
   // string vec_c_1_str[testcase.SENDER_LEN+100];
    for (auto i = 0; i < testcase.RECEIVER_LEN; i++) {
         Q_4[i]=(com_pp.g*BN_UID[i]+com_pp.vec_h[i]*BN_sk[i])*BN_c_1[i]+com_pp.g*s_1[i]+com_pp.vec_h[i]*s_2[i];
         //std::cout<<"Hash::ECPointToString(Q_4[i])"<<Hash::ECPointToString(Q_4[i])<<std::endl;
         Q_5[i]=u[i]*BN_c_1[i]+W[i]*s_1[i];
         //std::cout<<"Hash::ECPointToString(Q_5[i])"<<Hash::ECPointToString(Q_5[i])<<std::endl;

         Q_4_str[i]+=Hash::ECPointToString(Q_4[i]);
         // std::cout<<"Q_4_str[i]"<<Q_4_str[i]<<std::endl;
         Q_5_str[i]+=Hash::ECPointToString(Q_5[i]);
         // std::cout<<"Q_5_str[i]"<<Q_5_str[i]<<std::endl;
         Q_6_str[i]=Q_4_str[i]+Q_5_str[i];
        //std::cout<<"Q_6_str[i]"<<Q_6_str[1]<<std::endl;
         length_1[i]=Q_6_str[i].length();
         //length_2[i]=Q_2_str[i].length();
       //std::cout<<"Q_6_str[i]"<<Q_6_str[i]<<std::endl;

         BasicHash((uint8_t*)((Q_6_str.data())+i),sizeof(length_1[i]), vec_c_2[i].data());
         //std::cout<<"vec_c_1[i].data()"<<vec_c_2[i].data()<<std::endl;
         //std::cout<<"vec_c_2[i].data()"<<vec_c_1[i].data()<<std::endl;
          //string result2 = sha256(Q_6_str[i]);
          string vec_c_2_str( (char*) vec_c_2[i].data());
          BN_c_2[i]=Hash::StringToBigInt(vec_c_2_str);
          //std::cout<<"vec_c_2_str"<<vec_c_2_str<<std::endl;
         result2[i] = sha256(Q_6_str[i]);
         //std::cout<<"222222222222222222"<<result1[i] <<result2[i] <<std::endl;
           vec_condition[i] = (result1[i] == result2[i]); 
       //std::cout<<"vec_condition[i]"<<vec_condition[i]<<std::endl;
        
    }  

    auto end_time = std::chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    std::cout << "Authorization takes time = " 
              << std::chrono::duration <double, std::milli> (running_time).count() << " ms" << std::endl;

    PrintTestCase(testcase); 

    std::string party;

    std::cout << "please select your role between sender and receiver (hint: first start receiver, then start sender) ==> "; 

    std::getline(std::cin, party);
    PrintSplitLine('-'); 

    if(party == "sender"){
        NetIO client("client", "127.0.0.1", 8080);        
        mqRPMTPSI::Send(client, pp, testcase.vec_X,testcase.vec_D);
    } 

    if(party == "receiver"){
        NetIO server("server", "127.0.0.1", 8080);
        std::vector<block> vec_intersection_prime = mqRPMTPSI::Receive(server, pp, testcase.vec_Y);
        std::set<block, BlockCompare> set_diff_result = 
            ComputeSetDifference(vec_intersection_prime, testcase.vec_intersection);  

        double error_probability = set_diff_result.size()/double(testcase.vec_intersection.size()); 
        std::cout << "mqRPMT-based PSI test succeeds with probability " << (1 - error_probability) << std::endl; 
    }

    CRYPTO_Finalize();   
    
    return 0; 
}