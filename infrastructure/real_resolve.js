// This is a Node.js script dedicated to resolving DIDs using the official library.

const { Resolver } = require('did-resolver');
const { getResolver } = require('ethr-did-resolver');

// 1. Receive arguments from the command line: Python will pass arguments here
// args[0] is the DID, args[1] is the API URL. Optional args configure a
// private/local network without weakening the historical two-argument Sepolia
// entry point: args[2] network name, args[3] chain ID, args[4] registry.
const args = process.argv.slice(2);
const did = args[0];
const rpcUrl = args[1];
const networkName = args[2] || "sepolia";
const chainId = args[3] ? Number(args[3]) : 11155111;
const registry = args[4] || "0x03d5003bf0e79C5F5223588F347ebA39AfbC3818";

if (!did || !rpcUrl || !Number.isSafeInteger(chainId) || chainId <= 0) {
    console.error("Error: Please provide a DID and an RPC URL");
    process.exit(1);
}

async function run() {
    try {
        // 2. Configure connection
        const providerConfig = {
            networks: [
                {
                    name: networkName,
                    rpcUrl: rpcUrl,
                    chainId: chainId,
                    registry: registry
                }
            ]
        };

        // 3. Initialize the official resolver
        const ethrDidResolver = getResolver(providerConfig);
        const didResolver = new Resolver(ethrDidResolver);

        // 4. Execute resolution (fetches data from the chain)
        const doc = await didResolver.resolve(did);

        // 5. Print the result as a JSON string (Python will capture this output)
        console.log(JSON.stringify(doc, null, 4));

    } catch (error) {
        console.error("Error during resolution:", error);
        process.exit(1);
    }
}

run();
