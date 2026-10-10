use ristretto_vm::{ClassPath, ConfigurationBuilder, VM};

wit_bindgen::generate!({ path: "wit", world: "xerces" });

struct Engine;

impl Engine {
    fn invoke(class: &str, method: &str, arguments: &[String]) -> Result<String, String> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|error| error.to_string())?;
        runtime.block_on(async {
            let configuration = ConfigurationBuilder::new()
                .java_home("/jdk".into())
                .class_path(ClassPath::from(&[
                    "/app/classes",
                    "/app/vendor/xercesImpl-2.12.2.jar",
                    "/app/vendor/xml-apis-1.4.01.jar",
                ]))
                .interpreted(true)
                .add_system_property("os.name", "Linux")
                .add_system_property("user.dir", "/input")
                .add_system_property("java.io.tmpdir", "/tmp")
                .add_system_property("file.encoding", "UTF-8")
                .build()
                .map_err(|error| error.to_string())?;
            let vm = VM::new(configuration)
                .await
                .map_err(|error| error.to_string())?;
            match vm
                .try_invoke(class, method, arguments)
                .await
            {
                Ok(value) => value.as_string().map_err(|error| error.to_string()),
                Err(error) => {
                    // Format the throwable while its VM and GC heap are still alive.
                    if let ristretto_vm::Error::Throwable(ref throwable) = error {
                        let _ = vm.invoke(
                            "java.lang.Throwable",
                            "printStackTrace()V",
                            std::slice::from_ref(throwable),
                        ).await;
                        if let Ok(value) = vm.try_invoke(
                            "java.lang.Throwable",
                            "toString()Ljava/lang/String;",
                            std::slice::from_ref(throwable),
                        ).await {
                            if let Ok(message) = value.as_string() {
                                return Err(message);
                            }
                        }
                    }
                    Err(error.to_string())
                }
            }
        })
    }
}

impl Guest for Engine {
    fn parse(path: String) -> Result<String, String> {
        Engine::invoke("ParseXml", "parse(Ljava/lang/String;)Ljava/lang/String;", &[path])
    }

    fn probe() -> Result<String, String> {
        Engine::invoke("ProbeSandbox", "probe()Ljava/lang/String;", &[])
    }
}

export!(Engine);
