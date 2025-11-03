use tonic::transport::Server;

mod models;
mod utils;
mod iam_manager;

pub mod iam {
    tonic::include_proto!("iam");
}

use iam::iam_service_server::IamServiceServer;
use iam_manager::IamManager;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let addr = "[::1]:50051".parse()?;
    let iam_manager = IamManager::new();

    println!("IAM gRPC Server listening on {}", addr);

    Server::builder()
        .add_service(IamServiceServer::new(iam_manager))
        .serve(addr)
        .await?;

    Ok(())
}